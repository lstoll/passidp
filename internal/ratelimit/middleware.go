package ratelimit

import (
	"net"
	"net/http"
	"runtime"
	"sync"
	"weak"

	"golang.org/x/time/rate"
)

const (
	defaultRate  = rate.Limit(0.5)
	defaultBurst = 10
)

// Middleware provides HTTP rate limiting per IP address using a token bucket
// algorithm.
type Middleware struct {
	cache    *sync.Map // map[string]weak.Pointer[rate.Limiter]
	initOnce sync.Once

	// Rate is the sustained rate limit in requests per second. This is the rate
	// at which tokens are added to the token bucket. A value of 2 means 2
	// requests per second on average. If zero, defaults to defaultRate (0.5) on
	// first use.
	Rate rate.Limit

	// Burst is the maximum number of requests that can be processed immediately
	// before rate limiting kicks in. This allows for traffic spikes. A value of
	// 5 means the first 5 requests are allowed immediately, then subsequent
	// requests are limited by Rate. If zero, defaults to defaultBurst (5) on
	// first use.
	Burst int
}

// Wrap returns an HTTP handler that rate limits requests based on the client's
// IP address. Requests that exceed the rate limit receive a 429 Too Many
// Requests response.
//
// IP addresses are extracted from r.RemoteAddr. Note that if the server is
// behind a proxy/load balancer, r.RemoteAddr will be the proxy's IP unless
// middleware (like proxyhdrs.RemoteIP) has already updated it.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.initOnce.Do(func() {
			m.cache = &sync.Map{}
			// Only set defaults if not already configured
			if m.Rate == 0 {
				m.Rate = defaultRate
			}
			if m.Burst == 0 {
				m.Burst = defaultBurst
			}
		})

		// Extract IP address from RemoteAddr
		// If RemoteAddr doesn't contain a port (e.g., unix socket), use the whole address
		ip := r.RemoteAddr
		if parsedIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = parsedIP
		}

		if !m.getLimiter(ip).Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Middleware) getLimiter(ip string) *rate.Limiter {
	for {
		val, ok := m.cache.Load(ip)
		if ok {
			wp := val.(weak.Pointer[rate.Limiter])
			if l := wp.Value(); l != nil {
				return l
			}
			// Weak pointer was cleared (limiter was GC'd), remove from cache
			m.cache.CompareAndDelete(ip, val)
		}

		// Create a new limiter for this IP
		newLimiter := rate.NewLimiter(m.Rate, m.Burst)
		wp := weak.Make(newLimiter)

		// Try to store it. LoadOrStore handles the race condition where two
		// requests for the same IP come in concurrently.
		_, loaded := m.cache.LoadOrStore(ip, wp)
		if !loaded {
			// Success: We installed the new limiter.
			// Attach a cleanup function that runs when the limiter is GC'd.
			// This removes the stale entry from the cache.
			runtime.AddCleanup(newLimiter, func(ipAddr string) {
				m.cache.CompareAndDelete(ipAddr, wp)
			}, ip)

			return newLimiter
		}
		// Another goroutine beat us to it, loop and try to use their limiter
	}
}

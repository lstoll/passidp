/**
 * Modern WebAuthn implementation for browser-based authentication
 * @typedef {Object} RegistrationData
 * @property {string} keyName - The name for the key being registered
 *
 * @typedef {Object} CredentialResponse
 * @property {string} id - The credential ID
 * @property {string} rawId - Base64 encoded raw ID
 * @property {string} type - The credential type
 * @property {Object} response - The credential response data
 */

class WebAuthn {
    /**
     * Decode a base64 string into a Uint8Array
     * @param {string} value - Base64 encoded string
     * @returns {Uint8Array} Decoded buffer
     */
    static _decodeBuffer(value) {
        return Uint8Array.from(atob(value
            .replace(/-/g, "+")
            .replace(/_/g, "/")
        ), c => c.charCodeAt(0));
    }

    /**
     * Encode an ArrayBuffer into a url-safe base64 string
     * @param {ArrayBuffer} value - Buffer to encode
     * @returns {string} URL-safe base64 string
     */
    static _encodeBuffer(value) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=/g, "");
    }

    /**
     * Check if the response status matches the expected status
     * @param {number} status - Expected HTTP status code
     * @returns {Function} Response handler function
     */
    static _checkStatus(status) {
        return res => {
            if (res.status === status) {
                return res;
            }
            throw new Error(`HTTP ${res.status}: ${res.statusText}`);
        };
    }

    /**
     * Register a new WebAuthn credential
     * @param {RegistrationData} data - Registration data
     * @returns {Promise<Response>} Registration response
     */
    async register(data) {
        const response = await fetch('/registration/begin?key_name=' + encodeURIComponent(data.keyName), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const res = await WebAuthn._checkStatus(200)(response);
        const registrationData = await res.json();

        // Decode challenge and user ID
        registrationData.publicKey.challenge = WebAuthn._decodeBuffer(registrationData.publicKey.challenge);
        registrationData.publicKey.user.id = WebAuthn._decodeBuffer(registrationData.publicKey.user.id);

        // Decode exclude credentials if present
        if (registrationData.publicKey.excludeCredentials) {
            registrationData.publicKey.excludeCredentials.forEach(credential => {
                credential.id = WebAuthn._decodeBuffer(credential.id);
            });
        }

        const credential = await navigator.credentials.create(registrationData);

        const finishResponse = await fetch('/registration/finish', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: credential.id,
                rawId: WebAuthn._encodeBuffer(credential.rawId),
                response: {
                    attestationObject: WebAuthn._encodeBuffer(credential.response.attestationObject),
                    clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON)
                },
                type: credential.type
            }),
        });

        return WebAuthn._checkStatus(200)(finishResponse);
    }

    /**
     * Authenticate with WebAuthn using discoverable credentials
     * @param {string} sessionID - Session identifier
     * @returns {Promise<Response>} Authentication response
     */
    async login(sessionID) {
        const response = await fetch(`/start?sessionID=${encodeURIComponent(sessionID)}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({})
        });

        const res = await WebAuthn._checkStatus(200)(response);
        const authData = await res.json();

        // Decode challenge
        authData.publicKey.challenge = WebAuthn._decodeBuffer(authData.publicKey.challenge);

        // Decode allow credentials if present
        if (authData.publicKey.allowCredentials) {
            authData.publicKey.allowCredentials.forEach(credential => {
                credential.id = WebAuthn._decodeBuffer(credential.id);
            });
        }

        const credential = await navigator.credentials.get(authData);

        const finishResponse = await fetch(`/finish?sessionID=${encodeURIComponent(sessionID)}`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                id: credential.id,
                rawId: WebAuthn._encodeBuffer(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON),
                    authenticatorData: WebAuthn._encodeBuffer(credential.response.authenticatorData),
                    signature: WebAuthn._encodeBuffer(credential.response.signature),
                    userHandle: WebAuthn._encodeBuffer(credential.response.userHandle)
                }
            }),
        });

        return WebAuthn._checkStatus(200)(finishResponse);
    }

    /**
     * Authenticate with WebAuthn using embedded challenge and flow ID
     * @param {string} challenge - Base64 encoded challenge from the page
     * @param {string} flowID - Flow identifier
     * @returns {Promise<Object>} Authentication response with returnTo or error
     */
    async loginWithEmbeddedChallenge(challenge, flowID) {
        // Decode the challenge
        const decodedChallenge = WebAuthn._decodeBuffer(challenge);

        // Create the authentication options
        const authOptions = {
            publicKey: {
                challenge: decodedChallenge,
                rpId: window.location.hostname,
                allowCredentials: [], // Empty array for discoverable credentials
                userVerification: 'preferred'
            }
        };

        const credential = await navigator.credentials.get(authOptions);

        const finishResponse = await fetch('/finishWebauthnLogin', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                flowID: flowID,
                credentialAssertionResponse: {
                    id: credential.id,
                    rawId: WebAuthn._encodeBuffer(credential.rawId),
                    type: credential.type,
                    response: {
                        clientDataJSON: WebAuthn._encodeBuffer(credential.response.clientDataJSON),
                        authenticatorData: WebAuthn._encodeBuffer(credential.response.authenticatorData),
                        signature: WebAuthn._encodeBuffer(credential.response.signature),
                        userHandle: WebAuthn._encodeBuffer(credential.response.userHandle)
                    }
                }
            }),
        });

        const res = await WebAuthn._checkStatus(200)(finishResponse);
        return await res.json();
    }
}

/**
 * WebAuthn UI Manager - Handles DOM interactions and event binding
 */
class WebAuthnUI {
    constructor() {
        this.webauthn = new WebAuthn();
        this.registrationPending = false;
        this.loginPending = false;
        this.bindEvents();

        // Auto-login on page load (like the original onload="doLogin()")
        this.autoLogin();
    }

    /**
     * Get embedded challenge and flow ID from the page
     * @returns {Object} Object containing challenge and flowID
     */
    getEmbeddedData() {
        const flowElement = document.querySelector('[data-flow-id]');
        const challengeElement = document.querySelector('[data-webauthn-challenge]');

        if (!flowElement || !challengeElement) {
            throw new Error('Required embedded data not found on page');
        }

        return {
            flowID: flowElement.dataset.flowId,
            challenge: challengeElement.dataset.webauthnChallenge
        };
    }

    /**
     * Auto-login on page load
     */
    async autoLogin() {
        // Only auto-login if we're on a login page (has login form or button)
        // and NOT on a registration page
        const loginForm = document.getElementById('login-form');
        const loginButton = document.getElementById('login-button');
        const registerButton = document.getElementById('register-button');

        if ((loginForm || loginButton) && !registerButton) {
            // Small delay to ensure page is fully loaded
            setTimeout(() => {
                this.handleLogin();
            }, 100);
        }
    }

    /**
     * Bind event listeners to DOM elements
     */
    bindEvents() {
        // Registration button
        const registerButton = document.getElementById('register-button');
        if (registerButton) {
            registerButton.addEventListener('click', () => this.handleRegister());
        }

        // Login button
        const loginButton = document.getElementById('login-button');
        if (loginButton) {
            loginButton.addEventListener('click', () => this.handleLogin());
        }

        // Form submission handlers
        const registerForm = document.getElementById('register-form');
        if (registerForm) {
            registerForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleRegister();
            });
        }

        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleLogin();
            });
        }

        // Error message close button
        const errorDeleteButton = document.querySelector('#error-message .delete');
        if (errorDeleteButton) {
            errorDeleteButton.addEventListener('click', () => {
                this.hideError();
            });
        }
    }

    /**
     * Handle registration process
     */
    async handleRegister() {
        if (this.registrationPending) return;

        const keyNameInput = document.getElementById('keyName');
        if (!keyNameInput || !keyNameInput.value.trim()) {
            this.showError('Please enter a key name');
            return;
        }

        this.registrationPending = true;
        this.setLoadingState('register', true);
        this.hideError();

        try {
            const result = await this.webauthn.register({
                keyName: keyNameInput.value.trim()
            });

            // Parse the response
            const responseData = await result.json();

            if (responseData.success) {
                // Build success message with confirmation details
                let successMsg = responseData.message || "Passkey registered successfully!";
                if (responseData.confirmation_key) {
                    successMsg += `\n\nConfirmation Key: ${responseData.confirmation_key}`;
                }
                if (responseData.enrollment_id) {
                    successMsg += `\nEnrollment ID: ${responseData.enrollment_id}`;
                }
                // Store confirmation details in data attributes for easy extraction
                if (responseData.confirmation_key) {
                    document.body.dataset.confirmationKey = responseData.confirmation_key;
                }
                if (responseData.enrollment_id) {
                    document.body.dataset.enrollmentId = responseData.enrollment_id;
                }
                // Show success message
                this.showSuccess(successMsg);

                // Don't redirect automatically when confirmation is needed
                if (!responseData.confirmation_key && responseData.returnTo) {
                    setTimeout(() => {
                        window.location.href = responseData.returnTo;
                    }, 2000);
                }
            } else {
                this.showError(responseData.error || "Registration failed");
            }
        } catch (error) {
            console.error('Registration failed:', error);
            this.showError(`Failed to register key: ${error.message}`);
        } finally {
            this.registrationPending = false;
            this.setLoadingState('register', false);
        }
    }

    /**
     * Handle login process
     */
    async handleLogin() {
        if (this.loginPending) return;

        this.loginPending = true;
        this.setLoadingState('login', true);
        this.hideError();

        try {
            // Get embedded challenge data
            const embeddedData = this.getEmbeddedData();

            // Use embedded challenge flow
            const result = await this.webauthn.loginWithEmbeddedChallenge(
                embeddedData.challenge,
                embeddedData.flowID
            );

            if (result.error) {
                this.showError(result.error);
            } else if (result.returnTo) {
                // Redirect to the return URL
                window.location.href = result.returnTo;
            } else {
                this.showError('Invalid response from server');
            }
        } catch (error) {
            console.error('Login failed:', error);
            this.showError(`Failed to login: ${error.message}`);
        } finally {
            this.loginPending = false;
            this.setLoadingState('login', false);
        }
    }

    /**
     * Show success message to user
     * @param {string} message - Success message
     */
    showSuccess(message) {
        console.log("WebAuthnUI.showSuccess", message);
        // Try to find a success display element
        const successElement = document.getElementById('success-message');
        const successTextElement = document.querySelector('#success-message .success-text');

        if (successElement && successTextElement) {
            successTextElement.textContent = message;
            successElement.style.display = 'block';

            // Auto-hide after 5 seconds
            setTimeout(() => {
                this.hideSuccess();
            }, 5000);
        } else {
            // Fallback to alert
            alert(message);
        }
    }

    /**
     * Show error message to user
     * @param {string} message - Error message
     */
    showError(message) {
        console.error("WebAuthnUI.showError", message);
        // Try to find an error display element
        const errorElement = document.getElementById('error-message');
        const errorTextElement = document.querySelector('#error-message .error-text');

        if (errorElement && errorTextElement) {
            errorTextElement.textContent = message;
            errorElement.style.display = 'block';

            // Auto-hide after 10 seconds
            setTimeout(() => {
                this.hideError();
            }, 10000);
        } else {
            // Fallback to alert
            alert(message);
        }
    }

    /**
     * Hide success message
     */
    hideSuccess() {
        const successElement = document.getElementById('success-message');
        if (successElement) {
            successElement.style.display = 'none';
        }
    }

    /**
     * Hide error message
     */
    hideError() {
        const errorElement = document.getElementById('error-message');
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    }

    /**
     * Set loading state for buttons
     * @param {string} action - 'register' or 'login'
     * @param {boolean} isLoading - Whether to show loading state
     */
    setLoadingState(action, isLoading) {
        const button = document.getElementById(`${action}-button`);
        const loadingElement = document.getElementById(`${action}-loading`);

        if (button) {
            button.disabled = isLoading;
            if (isLoading) {
                button.dataset.originalText = button.textContent;
                button.textContent = 'Processing...';
            } else if (button.dataset.originalText) {
                button.textContent = button.dataset.originalText;
            }
        }

        if (loadingElement) {
            loadingElement.style.display = isLoading ? 'block' : 'none';
        }
    }
}

// Initialize WebAuthn UI when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new WebAuthnUI();
});

// Export for potential module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { WebAuthn, WebAuthnUI };
}

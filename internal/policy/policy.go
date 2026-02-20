package policy

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"
	"lds.li/passidp/claims"
	"lds.li/passidp/internal/config"
)

type PolicyEvaluator struct {
	env      *cel.Env
	programs sync.Map // map[string]cel.Program
}

func NewPolicyEvaluator() (*PolicyEvaluator, error) {
	var env *cel.Env
	var err error
	env, err = cel.NewEnv(
		cel.StdLib(),
		cel.Container("passidp.claims"),
		cel.Types(&claims.IDClaims{}),
		cel.Variable("claims", cel.ObjectType("passidp.claims.IDClaims")),
		cel.Variable("user", cel.MapType(cel.StringType, cel.DynType)),
		cel.Function("patch",
			cel.MemberOverload("claims_patch_map",
				[]*cel.Type{cel.ObjectType("passidp.claims.IDClaims"), cel.MapType(cel.StringType, cel.AnyType)},
				cel.ObjectType("passidp.claims.IDClaims"),
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					c, ok := lhs.Value().(*claims.IDClaims)
					if !ok {
						return types.NewErr("lhs is not IDClaims, got %T", lhs.Value())
					}

					nativeMap, err := rhs.ConvertToNative(reflect.TypeOf(map[string]any{}))
					if err != nil {
						return types.NewErr("failed to convert rhs to map: %v", err)
					}
					m := nativeMap.(map[string]any)

					ret := proto.Clone(c).(*claims.IDClaims)
					refRet := ret.ProtoReflect()
					desc := refRet.Descriptor()

					for k, v := range m {
						// Look up field by JSON name or proto name
						fd := desc.Fields().ByJSONName(k)
						if fd == nil {
							fd = desc.Fields().ByName(protoreflect.Name(k))
						}
						if fd == nil {
							return types.NewErr("field %s not found in IDClaims", k)
						}

						if v == nil || v == structpb.NullValue_NULL_VALUE {
							refRet.Clear(fd)
							continue
						}

						// Handle list/repeated fields (like groups)
						if fd.IsList() {
							list := refRet.Mutable(fd).List()
							// Clear existing
							for list.Len() > 0 {
								list.Truncate(0)
							}
							if g, ok := v.([]any); ok {
								for _, gi := range g {
									list.Append(protoreflect.ValueOf(gi))
								}
							}
							continue
						}

						// Set scalar fields
						refRet.Set(fd, protoreflect.ValueOf(v))
					}
					return env.CELTypeAdapter().NativeToValue(ret)
				}),
			),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("new cel env: %w", err)
	}
	return &PolicyEvaluator{env: env}, nil
}

func (pe *PolicyEvaluator) getProgram(expression string) (cel.Program, error) {
	if val, ok := pe.programs.Load(expression); ok {
		return val.(cel.Program), nil
	}

	ast, issues := pe.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compile: %w", issues.Err())
	}

	prg, err := pe.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("program: %w", err)
	}

	pe.programs.Store(expression, prg)
	return prg, nil
}

func (pe *PolicyEvaluator) EvaluateAuthorization(expression string, user *config.User) (bool, error) {
	if expression == "" {
		return true, nil
	}

	prg, err := pe.getProgram(expression)
	if err != nil {
		return false, err
	}

	userData := map[string]any{
		"id":       user.ID.String(),
		"email":    user.Email,
		"fullName": user.FullName,
		"groups":   user.Groups,
		"metadata": user.Metadata,
	}

	out, _, err := prg.Eval(map[string]any{
		"user": userData,
	})
	if err != nil {
		return false, fmt.Errorf("eval: %w", err)
	}

	val, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return a boolean, got %T", out.Value())
	}

	return val, nil
}

func (pe *PolicyEvaluator) EvaluateClaims(expression string, initialClaims *claims.IDClaims, user *config.User) (*claims.IDClaims, error) {
	if expression == "" {
		return initialClaims, nil
	}

	prg, err := pe.getProgram(expression)
	if err != nil {
		return nil, err
	}

	userData := map[string]any{
		"id":       user.ID.String(),
		"email":    user.Email,
		"fullName": user.FullName,
		"groups":   user.Groups,
		"metadata": user.Metadata,
	}

	out, _, err := prg.Eval(map[string]any{
		"claims": initialClaims,
		"user":   userData,
	})
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}

	if out.Type() == types.NullType {
		return initialClaims, nil
	}

	if idClaims, ok := out.Value().(*claims.IDClaims); ok {
		return idClaims, nil
	}
	return nil, fmt.Errorf("expression did not return an IDClaims object, returned %T", out.Value())
}

func (pe *PolicyEvaluator) Validate(expression string) error {
	if expression == "" {
		return nil
	}
	_, err := pe.getProgram(expression)
	return err
}

func ValidatePolicies(cfg *config.Config) error {
	pe, err := NewPolicyEvaluator()
	if err != nil {
		return fmt.Errorf("creating policy evaluator: %w", err)
	}

	for _, cl := range cfg.Clients {
		if err := pe.Validate(cl.ClaimsPolicy); err != nil {
			return fmt.Errorf("client %s claims policy: %w", cl.ID, err)
		}
		if err := pe.Validate(cl.AuthorizationPolicy); err != nil {
			return fmt.Errorf("client %s authorization policy: %w", cl.ID, err)
		}
	}
	return nil
}

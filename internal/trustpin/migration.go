package trustpin

import (
	"encoding/base32"
	"encoding/base64"
	"errors"

	"github.com/golang/protobuf/proto"
)

type migrationPayload struct {
	OtpParameters []*migrationPayloadOTPParameters `protobuf:"bytes,1,rep,name=otp_parameters,json=otpParameters" json:"otp_parameters,omitempty"`
	Version       *int32                           `protobuf:"varint,2,opt,name=version" json:"version,omitempty"`
}

type migrationPayloadOTPParameters struct {
	Secret    []byte  `protobuf:"bytes,1,opt,name=secret" json:"secret,omitempty"`
	Name      *string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	Issuer    *string `protobuf:"bytes,3,opt,name=issuer" json:"issuer,omitempty"`
	Algorithm *int32  `protobuf:"varint,4,opt,name=algorithm" json:"algorithm,omitempty"`
	Digits    *int32  `protobuf:"varint,5,opt,name=digits" json:"digits,omitempty"`
	Type      *int32  `protobuf:"varint,6,opt,name=type" json:"type,omitempty"`
	Counter   *int64  `protobuf:"varint,7,opt,name=counter" json:"counter,omitempty"`
}

func (m *migrationPayload) Reset()         { *m = migrationPayload{} }
func (m *migrationPayload) String() string { return "migrationPayload" }
func (*migrationPayload) ProtoMessage()    {}

func (m *migrationPayloadOTPParameters) Reset()         { *m = migrationPayloadOTPParameters{} }
func (m *migrationPayloadOTPParameters) String() string { return "migrationPayloadOTPParameters" }
func (*migrationPayloadOTPParameters) ProtoMessage()    {}

func parseMigrationData(dataB64 string) ([]Account, error) {
	if dataB64 == "" {
		return nil, errors.New("empty migration data")
	}

	raw, err := base64.StdEncoding.DecodeString(dataB64)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(dataB64)
		if err != nil {
			raw, err = base64.URLEncoding.DecodeString(dataB64)
			if err != nil {
				return nil, err
			}
		}
	}

	var payload migrationPayload
	if err := proto.Unmarshal(raw, &payload); err != nil {
		return nil, err
	}

	out := make([]Account, 0, len(payload.OtpParameters))
	for _, param := range payload.OtpParameters {
		name := ""
		if param.Name != nil {
			name = *param.Name
		}

		issuer := ""
		if param.Issuer != nil {
			issuer = *param.Issuer
		}

		accountName := name
		if issuer != "" {
			if accountName != "" {
				accountName = issuer + ":" + accountName
			} else {
				accountName = issuer
			}
		}

		digits := DefaultDigits
		if param.Digits != nil {
			switch dv := int(*param.Digits); dv {
			case 6, 8:
				digits = dv
			case 1:
				digits = 6
			case 2:
				digits = 8
			default:
				digits = DefaultDigits
			}
		}

		out = append(out, Account{
			Name:     accountName,
			Secret:   base32.StdEncoding.EncodeToString(param.Secret),
			Interval: DefaultInterval,
			Digits:   digits,
		})
	}

	return out, nil
}

package main

import (
	"encoding/base32"
	"encoding/base64"
	"errors"

	"github.com/golang/protobuf/proto"
)

type MigrationPayload struct {
	OtpParameters []*MigrationPayload_OTPParameters `protobuf:"bytes,1,rep,name=otp_parameters,json=otpParameters" json:"otp_parameters,omitempty"`
	Version       *int32                            `protobuf:"varint,2,opt,name=version" json:"version,omitempty"`
}

type MigrationPayload_OTPParameters struct {
	Secret    []byte  `protobuf:"bytes,1,opt,name=secret" json:"secret,omitempty"`
	Name      *string `protobuf:"bytes,2,opt,name=name" json:"name,omitempty"`
	Issuer    *string `protobuf:"bytes,3,opt,name=issuer" json:"issuer,omitempty"`
	Algorithm *int32  `protobuf:"varint,4,opt,name=algorithm" json:"algorithm,omitempty"`
	Digits    *int32  `protobuf:"varint,5,opt,name=digits" json:"digits,omitempty"`
	Type      *int32  `protobuf:"varint,6,opt,name=type" json:"type,omitempty"`
	Counter   *int64  `protobuf:"varint,7,opt,name=counter" json:"counter,omitempty"`
}

func (m *MigrationPayload) Reset()         { *m = MigrationPayload{} }
func (m *MigrationPayload) String() string { return "MigrationPayload" }

func (*MigrationPayload) ProtoMessage() {
	// marker method required by proto
}

func (m *MigrationPayload_OTPParameters) Reset()         { *m = MigrationPayload_OTPParameters{} }
func (m *MigrationPayload_OTPParameters) String() string { return "MigrationPayload_OTPParameters" }

func (*MigrationPayload_OTPParameters) ProtoMessage() {
	// marker method required by proto
}
func parseMigrationData(dataB64 string) ([]Account, error) {
	if dataB64 == "" {
		return nil, errors.New("empty migration data")
	}
	// Try several base64 decoders to be permissive.
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

	var mp MigrationPayload
	if err := proto.Unmarshal(raw, &mp); err != nil {
		return nil, err
	}

	var out []Account
	for _, p := range mp.OtpParameters {
		name := ""
		if p.Name != nil {
			name = *p.Name
		}
		issuer := ""
		if p.Issuer != nil {
			issuer = *p.Issuer
		}

		acctName := name
		if issuer != "" {
			// follow label style Issuer:Name
			if acctName != "" {
				acctName = issuer + ":" + acctName
			} else {
				acctName = issuer
			}
		}

		// Encode secret as base32 so the rest of the code can decode it like other secrets.
		secretBase32 := base32.StdEncoding.EncodeToString(p.Secret)

		// The migration proto uses an enum for digits (not the literal digit count).
		// Map common enum values to actual digit lengths. If the value already
		// looks like a digit (6 or 8), use it directly; otherwise fall back to
		// sensible defaults.
		digits := defaultDigits
		if p.Digits != nil {
			dv := int(*p.Digits)
			switch dv {
			case 6, 8:
				digits = dv
			case 1:
				// common enum value for 6 digits in some migration payloads
				digits = 6
			case 2:
				// common enum value for 8 digits
				digits = 8
			default:
				digits = defaultDigits
			}
		}

		interval := defaultInterval
		// migration payload doesn't include period in many cases; keep default

		out = append(out, Account{
			Name:     acctName,
			Secret:   secretBase32,
			Interval: int64(interval),
			Digits:   digits,
		})
	}

	return out, nil
}

package jwt

import (
	"net/http"
	"net/url"
	"testing"
)

func TestGetTokenFromRequest(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "TestGetTokenFromRequest",
			args: args{
				r: &http.Request{
					Header: map[string][]string{
						"Authorization": {"Bearer 1234567890"},
					},
				},
			},
			want:    "1234567890",
			wantErr: false,
		},
		{
			name: "TestGetTokenFromRequest - no token",
			args: args{
				r: &http.Request{
					Header: map[string][]string{
						"Authorization": {""},
					},
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "TestGetTokenFromRequest - query param",
			args: args{
				r: &http.Request{
					Header: map[string][]string{
						"Authorization": {""},
					},
					URL: &url.URL{
						RawQuery: "token=123",
					},
				},
			},
			want:    "123",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTokenFromRequest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTokenFromRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetTokenFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

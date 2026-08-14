package main

import (
	"reflect"
	"testing"
)

func TestParseMFATypeIDs(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "legacy layout",
			html: `
				<div class="changeReAuthTypes" id="3"></div>
				<div class="changeReAuthTypes" id="10"></div>`,
			want: []string{"3", "10"},
		},
		{
			name: "new tab layout",
			html: `
				<div class="reauth-tab-item reauth-tab-active" id="tab_13" data-type="13"></div>
				<div class="reauth-tab-item" id="tab_3" data-type="3"></div>
				<a class="reauth-tab-more-item" id="10">OTP</a>`,
			want: []string{"13", "3", "10"},
		},
		{
			name: "fallback tab id and deduplicate",
			html: `
				<div class="reauth-tab-item" id="tab_13"></div>
				<div class="changeReAuthTypes" id="13"></div>
				<a class="reauth-tab-more-item"></a>`,
			want: []string{"13"},
		},
		{
			name: "unrelated elements",
			html: `<div id="3"></div>`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMFATypeIDs(tt.html)
			if err != nil {
				t.Fatalf("parseMFATypeIDs() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseMFATypeIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

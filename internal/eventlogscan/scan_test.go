package eventlogscan

import (
	"strings"
	"testing"
)

func TestNormalizeParamsValidation(t *testing.T) {
	t.Parallel()

	if _, err := normalizeParams(QueryParams{}); err == nil {
		t.Fatal("expected missing start/end time error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 20, EndTime: 10}); err == nil {
		t.Fatal("expected startTime > endTime error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20, PageNo: -1}); err == nil {
		t.Fatal("expected pageNo bounds error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20, PageSize: 1000}); err == nil {
		t.Fatal("expected pageSize bounds error")
	}
	if _, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20, SortBy: "unknown"}); err == nil {
		t.Fatal("expected sortBy whitelist error")
	}
}

func TestNormalizeParamsDefaults(t *testing.T) {
	t.Parallel()

	got, err := normalizeParams(QueryParams{StartTime: 10, EndTime: 20})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	if got.PageNo != DefaultPageNo {
		t.Fatalf("expected default pageNo=%d, got %d", DefaultPageNo, got.PageNo)
	}
	if got.PageSize != DefaultPageSize {
		t.Fatalf("expected default pageSize=%d, got %d", DefaultPageSize, got.PageSize)
	}
	if got.SortBy != DefaultSortBy {
		t.Fatalf("expected default sortBy=%s, got %s", DefaultSortBy, got.SortBy)
	}
	if got.SortOrder != DefaultSortOrder {
		t.Fatalf("expected default sortOrder=%s, got %s", DefaultSortOrder, got.SortOrder)
	}
}

func TestBuildResultFilterSemanticsAndKeyword(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		Sources:   []string{"security"},
		EventTypes: []string{
			"login",
		},
		Results:  []string{"fail", "success"},
		Username: strPtr("alice"),
		Keyword:  strPtr("failed"),
		PageNo:   1,
		PageSize: 20,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	pid := 101
	result := buildResult(params, []rawEvent{
		{
			NativeID:    "a",
			Timestamp:   1000,
			Source:      "system",
			EventType:   "process",
			EventLevel:  "info",
			EventCode:   "1000",
			EventAction: "start",
			Result:      "success",
			ProcessName: "cmd.exe",
			ProcessID:   &pid,
			Message:     "process started",
		},
		{
			NativeID:   "b",
			Timestamp:  1001,
			Source:     "security",
			EventType:  "logon",
			EventLevel: "warning",
			EventCode:  "4625",
			Result:     "failed",
			Username:   "alice",
			Message:    "user login failed",
		},
		{
			NativeID:   "c",
			Timestamp:  1002,
			Source:     "security",
			EventType:  "login",
			EventLevel: "info",
			EventCode:  "4624",
			Result:     "success",
			Username:   "bob",
			Message:    "user login success",
		},
	})

	if result.Total != 1 {
		t.Fatalf("expected total=1, got %d", result.Total)
	}
	if len(result.Rows) != 1 {
		t.Fatalf("expected rows=1, got %d", len(result.Rows))
	}
	if result.Rows[0].Source != "security" || result.Rows[0].Result != "fail" {
		t.Fatalf("unexpected row: %#v", result.Rows[0])
	}
}

func TestBuildResultSortingAndStablePagination(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		PageNo:    1,
		PageSize:  1,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	events := []rawEvent{
		{NativeID: "a", Timestamp: 2000, Source: "system", EventType: "system", Message: "first"},
		{NativeID: "b", Timestamp: 2000, Source: "system", EventType: "system", Message: "second"},
		{NativeID: "c", Timestamp: 1000, Source: "system", EventType: "system", Message: "third"},
	}

	page1 := buildResult(params, events)
	if page1.Total != 3 {
		t.Fatalf("expected total=3, got %d", page1.Total)
	}
	if !page1.HasMore {
		t.Fatal("expected page1 hasMore=true")
	}
	if len(page1.Rows) != 1 {
		t.Fatalf("expected page1 rows=1, got %d", len(page1.Rows))
	}

	params.PageNo = 2
	page2 := buildResult(params, events)
	if len(page2.Rows) != 1 {
		t.Fatalf("expected page2 rows=1, got %d", len(page2.Rows))
	}
	if page1.Rows[0].LogID == page2.Rows[0].LogID {
		t.Fatalf("expected stable page boundaries with different rows, got same logId=%s", page1.Rows[0].LogID)
	}

	params.PageNo = 3
	page3 := buildResult(params, events)
	if len(page3.Rows) != 1 {
		t.Fatalf("expected page3 rows=1, got %d", len(page3.Rows))
	}
	if page3.HasMore {
		t.Fatal("expected page3 hasMore=false")
	}
}

func TestNormalizeMappingWindowsLinuxAndFallback(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		PageNo:    1,
		PageSize:  10,
		SortBy:    "timestamp",
		SortOrder: "asc",
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	result := buildResult(params, []rawEvent{
		{
			NativeID:    "win-1",
			Timestamp:   10,
			Source:      "Security",
			EventType:   "logon",
			EventLevel:  "Warning",
			EventCode:   "4625",
			EventAction: "login",
			Result:      "failed",
			Message:     "An account failed to log on",
		},
		{
			NativeID:    "linux-1",
			Timestamp:   20,
			Source:      "auth",
			EventType:   "authentication",
			EventLevel:  "notice",
			EventCode:   "USER_LOGIN",
			EventAction: "",
			Result:      "success",
			Message:     "session opened for user root",
		},
		{
			NativeID:   "unknown-1",
			Timestamp:  30,
			Source:     "mystery",
			EventType:  "something-new",
			EventLevel: "mystery",
			EventCode:  "",
			Message:    "unknown event",
		},
	})
	if len(result.Rows) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(result.Rows))
	}

	if result.Rows[0].Source != "security" || result.Rows[0].EventType != "login" {
		t.Fatalf("unexpected windows normalization row: %#v", result.Rows[0])
	}
	if result.Rows[1].Source != "auth" || result.Rows[1].EventType != "login" {
		t.Fatalf("unexpected linux normalization row: %#v", result.Rows[1])
	}
	if result.Rows[2].Source != "other" || result.Rows[2].EventType != "other" || result.Rows[2].EventCode != "unknown" {
		t.Fatalf("unexpected fallback normalization row: %#v", result.Rows[2])
	}
}

func TestRawContentPolicyRedactionAndTruncation(t *testing.T) {
	t.Parallel()

	base := QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		PageNo:    1,
		PageSize:  10,
	}

	noRawParams, err := normalizeParams(base)
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	noRaw := buildResult(noRawParams, []rawEvent{
		{
			NativeID:   "raw-no",
			Timestamp:  10,
			Source:     "system",
			EventType:  "system",
			RawContent: map[string]any{"password": "abc"},
		},
	})
	if len(noRaw.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(noRaw.Rows))
	}
	if noRaw.Rows[0].RawContent != nil {
		t.Fatalf("expected rawContent omitted by default, got %#v", noRaw.Rows[0].RawContent)
	}

	withRawParams, err := normalizeParams(QueryParams{
		StartTime:         1,
		EndTime:           999999999,
		PageNo:            1,
		PageSize:          10,
		IncludeRawContent: true,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}
	withRaw := buildResult(withRawParams, []rawEvent{
		{
			NativeID:  "raw-yes",
			Timestamp: 20,
			Source:    "system",
			EventType: "system",
			RawContent: map[string]any{
				"password": "abc",
				"nested": map[string]any{
					"token": "secret-token",
				},
			},
		},
		{
			NativeID:  "raw-big",
			Timestamp: 21,
			Source:    "system",
			EventType: "system",
			RawContent: map[string]any{
				"blob": strings.Repeat("x", maxRawContentBytes+128),
			},
		},
	})
	if len(withRaw.Rows) != 2 {
		t.Fatalf("expected two rows, got %d", len(withRaw.Rows))
	}

	rowsByTS := map[int64]EventRow{}
	for _, row := range withRaw.Rows {
		rowsByTS[row.Timestamp] = row
	}

	redacted, ok := rowsByTS[20].RawContent.(map[string]any)
	if !ok {
		t.Fatalf("expected map rawContent, got %#v", rowsByTS[20].RawContent)
	}
	if redacted["password"] != "[REDACTED]" {
		t.Fatalf("expected password redacted, got %#v", redacted["password"])
	}
	nested, ok := redacted["nested"].(map[string]any)
	if !ok || nested["token"] != "[REDACTED]" {
		t.Fatalf("expected nested token redacted, got %#v", redacted["nested"])
	}

	truncated, ok := rowsByTS[21].RawContent.(map[string]any)
	if !ok {
		t.Fatalf("expected truncated map, got %#v", rowsByTS[21].RawContent)
	}
	if truncated["_truncated"] != true {
		t.Fatalf("expected _truncated=true, got %#v", truncated["_truncated"])
	}
}

func TestLogIDStabilityNativeAndFallback(t *testing.T) {
	t.Parallel()

	params, err := normalizeParams(QueryParams{
		StartTime: 1,
		EndTime:   999999999,
		PageNo:    1,
		PageSize:  10,
	})
	if err != nil {
		t.Fatalf("normalizeParams returned error: %v", err)
	}

	nativeEvent := rawEvent{
		NativeID:   "security:42",
		Timestamp:  100,
		Source:     "security",
		EventType:  "login",
		EventLevel: "warn",
		EventCode:  "4625",
		Message:    "native id event",
	}
	fallbackEvent := rawEvent{
		Timestamp:  200,
		Source:     "system",
		EventType:  "process",
		EventLevel: "info",
		EventCode:  "1000",
		Message:    "fallback id event",
	}

	run1 := buildResult(params, []rawEvent{nativeEvent, fallbackEvent})
	run2 := buildResult(params, []rawEvent{nativeEvent, fallbackEvent})
	if len(run1.Rows) != 2 || len(run2.Rows) != 2 {
		t.Fatalf("unexpected rows count: run1=%d run2=%d", len(run1.Rows), len(run2.Rows))
	}

	ids1 := map[int64]string{}
	ids2 := map[int64]string{}
	for _, row := range run1.Rows {
		ids1[row.Timestamp] = row.LogID
	}
	for _, row := range run2.Rows {
		ids2[row.Timestamp] = row.LogID
	}
	if ids1[100] != ids2[100] || ids1[200] != ids2[200] {
		t.Fatalf("expected stable log IDs across runs, got run1=%v run2=%v", ids1, ids2)
	}
	if !strings.HasPrefix(ids1[100], "native_") {
		t.Fatalf("expected native id prefix for native event, got %s", ids1[100])
	}
	if !strings.HasPrefix(ids1[200], "evt_") {
		t.Fatalf("expected fallback id prefix for non-native event, got %s", ids1[200])
	}
}

func strPtr(value string) *string {
	return &value
}

package report

import (
	"testing"

	"criptografia_go/internal/model"
)

// Verifica que Print no haga panic con resultado íntegro y alterado.
func TestPrintDoesNotPanic(t *testing.T) {
	r := model.PipelineResult{
		EventCount:  2,
		CountByType: map[string]int{model.EventGradeRegistered: 1, model.EventGradeModified: 1},
		HashPlain:   "aaa", HashEncrypted: "bbb", HashDecrypted: "aaa", Preserved: true,
	}
	Print(r)
	r.HashDecrypted, r.Preserved = "ccc", false
	Print(r)
}

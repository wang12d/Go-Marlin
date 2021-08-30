package marlin

const (
	minimumParameters = 2
)

type Proof []byte // The proof generate by marlin

type VerifyKey []byte // The verify key of the proof

type EvaluationResults [2]uint // The data evaluation results

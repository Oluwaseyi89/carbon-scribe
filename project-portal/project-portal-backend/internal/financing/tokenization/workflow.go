package tokenization

import (
	"context"
	"fmt"
)

type MintInput struct {
	AssetCode   string
	AssetIssuer string
	Amount      float64
	BatchSize   int
}

type MintOutcome struct {
	TransactionHash string
	TokenIDs        []string
	AssetCode       string
	AssetIssuer     string
	FinalStatus     string
}

type Workflow struct {
	client  Client
	monitor *Monitor
}

func NewWorkflow(client Client, monitor *Monitor) *Workflow {
	return &Workflow{client: client, monitor: monitor}
}

func (w *Workflow) Mint(ctx context.Context, input MintInput) (*MintOutcome, error) {
	resp, err := w.client.Mint(ctx, MintRequest{
		AssetCode:   input.AssetCode,
		AssetIssuer: input.AssetIssuer,
		Amount:      input.Amount,
		BatchSize:   input.BatchSize,
	})
	if err != nil {
		return nil, fmt.Errorf("mint transaction failed: %w", err)
	}
	finalStatus := w.monitor.ResolveFinalStatus("success")
	return &MintOutcome{
		TransactionHash: resp.TransactionHash,
		TokenIDs:        resp.TokenIDs,
		AssetCode:       resp.AssetCode,
		AssetIssuer:     resp.AssetIssuer,
		FinalStatus:     finalStatus,
	}, nil
}

package alerts

import (
	"fmt"

	"github.com/newrelic/newrelic-client-go/pkg/errors"
)

// ThresholdOccurance specifies the threshold occurance for NRQL alert condition terms.
type ThresholdOccurance string

var (
	// ThresholdOccurrences enumerates the possible threshold occurance values for NRQL alert condition terms.
	ThresholdOccurrences = struct {
		All         ThresholdOccurance
		AtLeastOnce ThresholdOccurance
	}{
		All:         "ALL",
		AtLeastOnce: "AT_LEAST_ONCE",
	}
)

// NrqlConditionType specifies the type of NRQL alert condition.
type NrqlConditionType string

var (
	// NrqlConditionTypes enumerates the possible NRQL condition type values for NRQL alert conditions.
	NrqlConditionTypes = struct {
		Baseline NrqlConditionType
		Static   NrqlConditionType
	}{
		Baseline: "BASELINE",
		Static:   "STATIC",
	}
)

// NrqlConditionValueFunction specifies the value function of NRQL alert condition.
type NrqlConditionValueFunction string

var (
	// NrqlConditionValueFunctions enumerates the possible NRQL condition value function values for NRQL alert conditions.
	NrqlConditionValueFunctions = struct {
		SingleValue NrqlConditionValueFunction
		Sum         NrqlConditionValueFunction
	}{
		SingleValue: "SINGLE_VALUE",
		Sum:         "SUM",
	}
)

// NrqlConditionValueFunction specifies the value function of NRQL alert condition.
type NrqlConditionViolationTimeLimit string

var (
	// NrqlConditionValueFunctions enumerates the possible NRQL condition violation time limit values for NRQL alert conditions.
	NrqlConditionViolationTimeLimits = struct {
		OneHour         NrqlConditionViolationTimeLimit
		TwoHours        NrqlConditionViolationTimeLimit
		FourHours       NrqlConditionViolationTimeLimit
		EightHours      NrqlConditionViolationTimeLimit
		TwelveHours     NrqlConditionViolationTimeLimit
		TwentyFourHours NrqlConditionViolationTimeLimit
	}{
		OneHour:         "ONE_HOUR",
		TwoHours:        "TWO_HOURS",
		FourHours:       "FOUR_HOURS",
		EightHours:      "EIGHT_HOURS",
		TwelveHours:     "TWELVE_HOURS",
		TwentyFourHours: "TWENTY_FOUR_HOURS",
	}
)

// NrqlConditionBase represents the base fields for a New Relic NRQL Alert condition. These fields
// shared between the NrqlConditionMutationInput struct and NrqlConditionMutationResponse struct.
type NrqlConditionBase struct {
	Name               string                          `json:"name,omitempty"`
	Enabled            string                          `json:"enabled"`
	Description        string                          `json:"description,omitempty"`
	Nrql               NrqlConditionQuery              `json:"nrql,omitempty"`
	RunbookURL         string                          `json:"runbookUrl,omitempty"`
	Terms              []NrqlConditionTerm             `json:"terms,omitempty"`
	Type               NrqlConditionType               `json:"type,omitempty"`
	ValueFunction      NrqlConditionValueFunction      `json:"value_function,omitempty"`
	ViolationTimeLimit NrqlConditionViolationTimeLimit `json:"violationTimeLimit,omitempty"`
}

// NrqlConditionMutationInput represents the NerdGraph mutation input that's used to generate a request.
type NrqlConditionMutationInput struct {
	ID       int `json:"id,omitempty"`
	PolicyID int `json:"policyId,omitempty"`
	NrqlConditionBase
}

// NrqlConditionMutationResponse represents the NerdGraph API response for a New Relic NRQL Alert condition.
type NrqlConditionMutationResponse struct {
	NrqlConditionBase
	ID       string `json:"id,omitempty"`
	PolicyID string `json:"name,omitempty"`
}

// ConditionTerm represents the terms of a New Relic alert condition.
type NrqlConditionTerm struct {
	Operator            OperatorType `json:"operator,omitempty"`
	Priority            PriorityType `json:"priority,omitempty"`
	Threshold           float64      `json:"threshold,string"`
	ThresholdDuration   int          `json:"thresholdDuration,string,omitempty"`
	ThresholdOccurances int          `json:"thresholdOccurrences,string,omitempty"`
}

// NrqlConditionQuery represents the NRQL query object returned in a NerdGraph response object.
type NrqlConditionQuery struct {
	Query            string `json:"query,omitempty"`
	EvaluationOffset string `json:"evaluationOffset,omitempty"`
}

//////////////////////////////////////////////////////////////////

// NrqlCondition represents a New Relic NRQL Alert condition.
type NrqlCondition struct {
	Terms               []ConditionTerm   `json:"terms,omitempty"`
	Nrql                NrqlQuery         `json:"nrql,omitempty"`
	Type                string            `json:"type,omitempty"`
	Name                string            `json:"name,omitempty"`
	RunbookURL          string            `json:"runbook_url,omitempty"`
	ValueFunction       ValueFunctionType `json:"value_function,omitempty"`
	ID                  int               `json:"id,omitempty"`
	ViolationCloseTimer int               `json:"violation_time_limit_seconds,omitempty"`
	ExpectedGroups      int               `json:"expected_groups,omitempty"`
	IgnoreOverlap       bool              `json:"ignore_overlap,omitempty"`
	Enabled             bool              `json:"enabled"`
}

// NrqlQuery represents a NRQL query to use with a NRQL alert condition
type NrqlQuery struct {
	Query      string `json:"query,omitempty"`
	SinceValue string `json:"since_value,omitempty"`
}

// ListNrqlConditions returns NRQL alert conditions for a specified policy.
func (a *Alerts) ListNrqlConditions(policyID int) ([]*NrqlCondition, error) {
	conditions := []*NrqlCondition{}
	queryParams := listNrqlConditionsParams{
		PolicyID: policyID,
	}

	nextURL := "/alerts_nrql_conditions.json"

	for nextURL != "" {
		response := nrqlConditionsResponse{}
		resp, err := a.client.Get(nextURL, &queryParams, &response)

		if err != nil {
			return nil, err
		}

		conditions = append(conditions, response.NrqlConditions...)

		paging := a.pager.Parse(resp)
		nextURL = paging.Next
	}

	return conditions, nil
}

// GetNrqlCondition gets information about a NRQL alert condition
// for a specified policy ID and condition ID.
func (a *Alerts) GetNrqlCondition(policyID int, id int) (*NrqlCondition, error) {
	conditions, err := a.ListNrqlConditions(policyID)
	if err != nil {
		return nil, err
	}

	for _, condition := range conditions {
		if condition.ID == id {
			return condition, nil
		}
	}

	return nil, errors.NewNotFoundf("no condition found for policy %d and condition ID %d", policyID, id)
}

// CreateNrqlCondition creates a NRQL alert condition.
func (a *Alerts) CreateNrqlCondition(policyID int, condition NrqlCondition) (*NrqlCondition, error) {
	reqBody := nrqlConditionRequestBody{
		NrqlCondition: condition,
	}
	resp := nrqlConditionResponse{}

	u := fmt.Sprintf("/alerts_nrql_conditions/policies/%d.json", policyID)
	_, err := a.client.Post(u, nil, &reqBody, &resp)

	if err != nil {
		return nil, err
	}

	return &resp.NrqlCondition, nil
}

// UpdateNrqlCondition updates a NRQL alert condition.
func (a *Alerts) UpdateNrqlCondition(condition NrqlCondition) (*NrqlCondition, error) {
	reqBody := nrqlConditionRequestBody{
		NrqlCondition: condition,
	}
	resp := nrqlConditionResponse{}

	u := fmt.Sprintf("/alerts_nrql_conditions/%d.json", condition.ID)
	_, err := a.client.Put(u, nil, &reqBody, &resp)

	if err != nil {
		return nil, err
	}

	return &resp.NrqlCondition, nil
}

// DeleteNrqlCondition deletes a NRQL alert condition.
func (a *Alerts) DeleteNrqlCondition(id int) (*NrqlCondition, error) {
	resp := nrqlConditionResponse{}
	u := fmt.Sprintf("/alerts_nrql_conditions/%d.json", id)

	_, err := a.client.Delete(u, nil, &resp)

	if err != nil {
		return nil, err
	}

	return &resp.NrqlCondition, nil
}

func (a *Alerts) CreateNrqlConditionMutation() (*NrqlCondition, error) {

}

type listNrqlConditionsParams struct {
	PolicyID int `url:"policy_id,omitempty"`
}

type nrqlConditionsResponse struct {
	NrqlConditions []*NrqlCondition `json:"nrql_conditions,omitempty"`
}

type nrqlConditionResponse struct {
	NrqlCondition NrqlCondition `json:"nrql_condition,omitempty"`
}

type nrqlConditionRequestBody struct {
	NrqlCondition NrqlCondition `json:"nrql_condition,omitempty"`
}

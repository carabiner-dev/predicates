// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"fmt"
	"slices"

	"github.com/carabiner-dev/attestation"
	papi "github.com/carabiner-dev/policy/api/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// PredicateTypes is a slice of all the predicate types
var PredicateTypes = []attestation.PredicateType{
	PolicyPredicateType,
	PolicySetPredicateType,
	PolicyGroupPredicateType,

	ResultPredicateType,
	ResultSetPredicateType,
	ResultGroupPredicateType,
}

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

func (p *Parser) ParsePolicySetPredicate(data []byte) (attestation.Predicate, error) {
	set := &papi.PolicySet{}
	if err := protojson.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &PolicySet{
		Parsed:       set,
		Data:         data,
		verification: nil,
	}, nil
}

func (p *Parser) ParsePolicyPredicate(data []byte) (attestation.Predicate, error) {
	policy := &papi.Policy{}
	if err := protojson.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	return &Policy{
		Data:   data,
		Parsed: policy,
	}, nil
}

func (p *Parser) ParsePolicyGroupPredicate(data []byte) (attestation.Predicate, error) {
	group := &papi.PolicyGroup{}
	if err := protojson.Unmarshal(data, group); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}
	return &PolicyGroup{
		Data:   data,
		Parsed: group,
	}, nil
}

func (p *Parser) ParseResultPredicate(data []byte) (attestation.Predicate, error) {
	res := &papi.Result{}
	if err := protojson.Unmarshal(data, res); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &Result{
		Parsed: res,
		Data:   data,
	}, nil
}

func (p *Parser) ParseResultSetPredicate(data []byte) (attestation.Predicate, error) {
	res := &papi.ResultSet{}
	if err := protojson.Unmarshal(data, res); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &ResultSet{
		Parsed: res,
		Data:   data,
	}, nil
}

func (p *Parser) ParseResultGroupPredicate(data []byte) (attestation.Predicate, error) {
	res := &papi.ResultGroup{}
	if err := protojson.Unmarshal(data, res); err != nil {
		return nil, fmt.Errorf("unmarshaling predicate data: %w", err)
	}

	return &ResultGroup{
		Parsed: res,
		Data:   data,
	}, nil
}

func (*Parser) SupportsType(predTypes ...attestation.PredicateType) bool {
	for _, p := range PredicateTypes {
		if slices.Contains(predTypes, p) {
			return true
		}
	}
	return false
}

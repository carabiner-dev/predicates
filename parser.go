// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicates

import (
	"fmt"
	"slices"
	"sync"

	"github.com/carabiner-dev/attestation"
	"google.golang.org/protobuf/encoding/protojson"

	papi "github.com/carabiner-dev/policy/api/v1"
)

// PredicateTypes is a slice of all the predicate types
var PredicateTypes = []attestation.PredicateType{
	PredicateTypePolicy,
	PolicySetPredicateType,
	PredicateTypePolicyGroup,

	PredicateTypeResult,
	PredicateTypeResultSet,
	PredicateTypeResultGroup,
}

func New() *Parser {
	return &Parser{}
}

type Parser struct{}

// Parse takes JSON data and returns any of the supported predicates if it parses
func (p *Parser) Parse(data []byte) (attestation.Predicate, error) {
	var o sync.Once
	var pred attestation.Predicate

	// This function catches the first predicate to be successfully parsed
	setPredicateIfNotNil := func(a attestation.Predicate, err error) {
		if err != nil {
			return
		}
		if pred != nil {
			return
		}
		o.Do(func() { pred = a })
	}

	var wg sync.WaitGroup
	wg.Add(6)

	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParsePolicyPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParsePolicySetPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParsePolicyGroupPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParseResultPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParseResultSetPredicate(data))
	}()
	go func() {
		defer wg.Done()
		setPredicateIfNotNil(p.ParseResultGroupPredicate(data))
	}()
	wg.Wait()

	if pred == nil {
		return nil, attestation.ErrNotCorrectFormat
	}
	return pred, nil
}

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

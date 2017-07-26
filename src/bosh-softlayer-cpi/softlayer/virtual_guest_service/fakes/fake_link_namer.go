// Code generated by counterfeiter. DO NOT EDIT.
package fakes

import (
	instance "bosh-softlayer-cpi/softlayer/virtual_guest_service"
	"sync"
)

type FakeLinkNamer struct {
	NameStub        func(interfaceName, networkName string) (string, error)
	nameMutex       sync.RWMutex
	nameArgsForCall []struct {
		interfaceName string
		networkName   string
	}
	nameReturns struct {
		result1 string
		result2 error
	}
	nameReturnsOnCall map[int]struct {
		result1 string
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeLinkNamer) Name(interfaceName string, networkName string) (string, error) {
	fake.nameMutex.Lock()
	ret, specificReturn := fake.nameReturnsOnCall[len(fake.nameArgsForCall)]
	fake.nameArgsForCall = append(fake.nameArgsForCall, struct {
		interfaceName string
		networkName   string
	}{interfaceName, networkName})
	fake.recordInvocation("Name", []interface{}{interfaceName, networkName})
	fake.nameMutex.Unlock()
	if fake.NameStub != nil {
		return fake.NameStub(interfaceName, networkName)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.nameReturns.result1, fake.nameReturns.result2
}

func (fake *FakeLinkNamer) NameCallCount() int {
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	return len(fake.nameArgsForCall)
}

func (fake *FakeLinkNamer) NameArgsForCall(i int) (string, string) {
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	return fake.nameArgsForCall[i].interfaceName, fake.nameArgsForCall[i].networkName
}

func (fake *FakeLinkNamer) NameReturns(result1 string, result2 error) {
	fake.NameStub = nil
	fake.nameReturns = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeLinkNamer) NameReturnsOnCall(i int, result1 string, result2 error) {
	fake.NameStub = nil
	if fake.nameReturnsOnCall == nil {
		fake.nameReturnsOnCall = make(map[int]struct {
			result1 string
			result2 error
		})
	}
	fake.nameReturnsOnCall[i] = struct {
		result1 string
		result2 error
	}{result1, result2}
}

func (fake *FakeLinkNamer) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.nameMutex.RLock()
	defer fake.nameMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeLinkNamer) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ instance.LinkNamer = new(FakeLinkNamer)

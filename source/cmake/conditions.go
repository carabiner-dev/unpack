// SPDX-FileCopyrightText: Copyright 2026 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmake

import "strings"

// This file follows the if() blocks of a CMake file, to tell whether the
// default configuration of the project runs a command.
//
// Conditions are evaluated as far as the files settle them: constants,
// options at their default and variables set to one literal value, with
// NOT, AND and OR. Anything else, the result of a lookup, the platform, a
// comparison, is unknown, and so is every command behind it.

// conditionState is whether a block runs.
type conditionState int

const (
	stateUnknown conditionState = iota
	stateOn
	stateOff
)

// conditionFrame is one open if() block.
type conditionFrame struct {
	// current is the state of the branch being read.
	current conditionState

	// taken says an earlier branch runs for sure, so no later one does;
	// open says an earlier branch may run, so a later one may not.
	taken bool
	open  bool
}

type conditionStack struct {
	frames []conditionFrame
}

// step follows a flow control command and says whether it was one.
func (s *conditionStack) step(command *Command, r *reader) bool {
	switch command.Name {
	case "if":
		state := r.evaluate(command.Args)
		s.frames = append(s.frames, conditionFrame{
			current: state, taken: state == stateOn, open: state == stateUnknown,
		})
	case "elseif":
		if len(s.frames) == 0 {
			return true
		}
		frame := &s.frames[len(s.frames)-1]
		frame.current = frame.next(r.evaluate(command.Args))
	case "else":
		if len(s.frames) == 0 {
			return true
		}
		frame := &s.frames[len(s.frames)-1]
		frame.current = frame.next(stateOn)
	case "endif":
		if len(s.frames) > 0 {
			s.frames = s.frames[:len(s.frames)-1]
		}
	default:
		return false
	}
	return true
}

// next gives the state of a later branch whose own condition evaluates
// to state, given the branches before it.
func (f *conditionFrame) next(state conditionState) conditionState {
	switch {
	case f.taken:
		return stateOff
	case state == stateOff:
		return stateOff
	case f.open || state == stateUnknown:
		f.open = true
		return stateUnknown
	default:
		f.taken = true
		return stateOn
	}
}

// state is whether a command here runs: not when any block around it
// does not, for sure only when every one does.
func (s *conditionStack) state() conditionState {
	state := stateOn
	for i := range s.frames {
		switch s.frames[i].current {
		case stateOff:
			return stateOff
		case stateUnknown:
			state = stateUnknown
		case stateOn:
		}
	}
	return state
}

// truth is CMake's reading of a constant.
func truth(value string) conditionState {
	switch upper := strings.ToUpper(value); {
	case upper == "ON" || upper == "TRUE" || upper == "YES" || upper == "Y" || upper == "1":
		return stateOn
	case upper == "OFF" || upper == "FALSE" || upper == "NO" || upper == "N" || upper == "0" ||
		upper == "IGNORE" || upper == "NOTFOUND" || upper == "" || strings.HasSuffix(upper, "-NOTFOUND"):
		return stateOff
	}
	return stateUnknown
}

// evaluate reads a condition: operands joined by AND and OR, each
// possibly behind a NOT. OR binds loosest, as in CMake. A condition with
// parentheses or any other operator is unknown.
func (r *reader) evaluate(args []Argument) conditionState {
	if len(args) == 0 {
		return stateOff
	}
	result := stateOff
	for _, alternative := range splitArgs(args, "OR") {
		all := stateOn
		for _, term := range splitArgs(alternative, "AND") {
			switch r.term(term) {
			case stateOff:
				all = stateOff
			case stateUnknown:
				if all == stateOn {
					all = stateUnknown
				}
			case stateOn:
			}
			if all == stateOff {
				break
			}
		}
		switch all {
		case stateOn:
			return stateOn
		case stateUnknown:
			result = stateUnknown
		case stateOff:
		}
	}
	return result
}

func splitArgs(args []Argument, keyword string) [][]Argument {
	parts := [][]Argument{{}}
	for _, arg := range args {
		if !arg.Quoted && arg.Value == keyword {
			parts = append(parts, []Argument{})
			continue
		}
		parts[len(parts)-1] = append(parts[len(parts)-1], arg)
	}
	return parts
}

// term reads one operand, with the NOTs before it.
func (r *reader) term(args []Argument) conditionState {
	negated := false
	for len(args) > 0 && !args[0].Quoted && args[0].Value == "NOT" {
		negated = !negated
		args = args[1:]
	}
	state := stateUnknown
	if len(args) == 1 {
		state = r.operand(args[0])
	}
	if !negated || state == stateUnknown {
		return state
	}
	if state == stateOn {
		return stateOff
	}
	return stateOn
}

// operand reads a constant, an option or a variable.
func (r *reader) operand(arg Argument) conditionState {
	value, resolved := r.expand(arg.Value)
	if !resolved {
		return stateUnknown
	}
	if state := truth(value); state != stateUnknown && (arg.Quoted || !r.named(value)) {
		return state
	}
	if arg.Quoted {
		return stateUnknown
	}
	if on, ok := r.options[value]; ok && !r.ambiguous[value] {
		// An option also set elsewhere may not be at its default.
		if _, set := r.variables[value]; !set {
			if on {
				return stateOn
			}
			return stateOff
		}
	}
	if defined, ok := r.variables[value]; ok && !r.ambiguous[value] {
		if _, isOption := r.options[value]; !isOption {
			// A variable is true unless it holds a false constant.
			if truth(defined) == stateOff {
				return stateOff
			}
			return stateOn
		}
	}
	return stateUnknown
}

// named says whether a value names an option or a variable of the files.
func (r *reader) named(value string) bool {
	_, option := r.options[value]
	_, variable := r.variables[value]
	return option || variable
}

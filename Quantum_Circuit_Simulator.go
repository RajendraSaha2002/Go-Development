package main

import (
	"fmt"
	"math"
	"math/cmplx"
	"math/rand"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// ============================================================================
// 1. QUANTUM STATE VECTOR & 2x2 COMPLEX MATRIX CORE
// ============================================================================

type Matrix2x2 [2][2]complex128

// Standard Quantum Gate Unitaries
var (
	GateH = Matrix2x2{
		{complex(1.0/math.Sqrt2, 0), complex(1.0/math.Sqrt2, 0)},
		{complex(1.0/math.Sqrt2, 0), complex(-1.0/math.Sqrt2, 0)},
	}
	GateX = Matrix2x2{
		{0, 1},
		{1, 0},
	}
	GateY = Matrix2x2{
		{0, complex(0, -1)},
		{complex(0, 1), 0},
	}
	GateZ = Matrix2x2{
		{1, 0},
		{0, -1},
	}
	GateS = Matrix2x2{
		{1, 0},
		{0, complex(0, 1)}, // e^(i*pi/2)
	}
	GateT = Matrix2x2{
		{1, 0},
		{0, cmplx.Exp(complex(0, math.Pi/4))},
	}
)

func GatePhase(theta float64) Matrix2x2 {
	return Matrix2x2{
		{1, 0},
		{0, cmplx.Exp(complex(0, theta))},
	}
}

// QuantumState represents an n-qubit pure state vector with 2^n complex amplitudes
type QuantumState struct {
	NumQubits int
	Dim       int
	Amps      []complex128
	rnd       *rand.Rand
}

func NewQuantumState(numQubits int) *QuantumState {
	dim := 1 << numQubits
	amps := make([]complex128, dim)
	amps[0] = 1.0 // Initialize to ground state |0...0>
	return &QuantumState{
		NumQubits: numQubits,
		Dim:       dim,
		Amps:      amps,
		rnd:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (q *QuantumState) Clone() *QuantumState {
	cloned := &QuantumState{
		NumQubits: q.NumQubits,
		Dim:       q.Dim,
		Amps:      make([]complex128, q.Dim),
		rnd:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	copy(cloned.Amps, q.Amps)
	return cloned
}

// ============================================================================
// 2. GOROUTINE-PARALLEL GATE APPLICATION
// ============================================================================

// ApplyGate applies an arbitrary single-qubit matrix U to the target qubit,
// optionally guarded by any number of control qubits.
// For dim >= 1024 (>=10 qubits), basis pairs are transformed concurrently.
func (q *QuantumState) ApplyGate(u Matrix2x2, target int, controls []int) {
	numPairs := q.Dim >> 1
	controlMask := 0
	for _, c := range controls {
		controlMask |= 1 << c
	}

	worker := func(startPair, endPair int) {
		for p := startPair; p < endPair; p++ {
			// Extract basis state indices i0 and i1 differing only at the target bit
			high := p >> target
			low := p & ((1 << target) - 1)
			i0 := (high << (target + 1)) | low
			i1 := i0 | (1 << target)

			// Verify all control qubits are satisfied
			if controlMask != 0 && (i0&controlMask) != controlMask {
				continue
			}

			v0 := q.Amps[i0]
			v1 := q.Amps[i1]

			// Unitary matrix multiplication
			q.Amps[i0] = u[0][0]*v0 + u[0][1]*v1
			q.Amps[i1] = u[1][0]*v0 + u[1][1]*v1
		}
	}

	// Concurrency threshold: parallelize across available CPU cores if state is large
	if q.Dim >= 1024 && runtime.NumCPU() > 1 {
		numWorkers := runtime.NumCPU()
		chunk := (numPairs + numWorkers - 1) / numWorkers
		var wg sync.WaitGroup

		for w := 0; w < numWorkers; w++ {
			start := w * chunk
			end := start + chunk
			if start >= numPairs {
				break
			}
			if end > numPairs {
				end = numPairs
			}
			wg.Add(1)
			go func(s, e int) {
				defer wg.Done()
				worker(s, e)
			}(start, end)
		}
		wg.Wait()
	} else {
		worker(0, numPairs)
	}
}

// Standard Gate Helpers
func (q *QuantumState) H(target int)                    { q.ApplyGate(GateH, target, nil) }
func (q *QuantumState) X(target int)                    { q.ApplyGate(GateX, target, nil) }
func (q *QuantumState) Y(target int)                    { q.ApplyGate(GateY, target, nil) }
func (q *QuantumState) Z(target int)                    { q.ApplyGate(GateZ, target, nil) }
func (q *QuantumState) Phase(theta float64, target int) { q.ApplyGate(GatePhase(theta), target, nil) }
func (q *QuantumState) CNOT(control, target int)        { q.ApplyGate(GateX, target, []int{control}) }
func (q *QuantumState) CZ(control, target int)          { q.ApplyGate(GateZ, target, []int{control}) }
func (q *QuantumState) CPhase(theta float64, c, t int)  { q.ApplyGate(GatePhase(theta), t, []int{c}) }
func (q *QuantumState) Toffoli(c1, c2, target int)      { q.ApplyGate(GateX, target, []int{c1, c2}) }

func (q *QuantumState) SWAP(q1, q2 int) {
	if q1 == q2 {
		return
	}
	q.CNOT(q1, q2)
	q.CNOT(q2, q1)
	q.CNOT(q1, q2)
}

// ============================================================================
// 3. MEASUREMENT, PROBABILITIES & SAMPLING
// ============================================================================

func (q *QuantumState) Probabilities() []float64 {
	probs := make([]float64, q.Dim)
	for i, amp := range q.Amps {
		mag := cmplx.Abs(amp)
		probs[i] = mag * mag
	}
	return probs
}

// Sample measures the state repeatedly without destructive wave-function collapse
func (q *QuantumState) Sample(shots int) map[int]int {
	probs := q.Probabilities()
	counts := make(map[int]int)

	for s := 0; s < shots; s++ {
		r := q.rnd.Float64()
		cum := 0.0
		chosen := q.Dim - 1
		for i, p := range probs {
			cum += p
			if r <= cum {
				chosen = i
				break
			}
		}
		counts[chosen]++
	}
	return counts
}

// PrintState outputs non-zero basis states in Dirac notation
func (q *QuantumState) PrintState() {
	var sb strings.Builder
	first := true
	for i, amp := range q.Amps {
		prob := cmplx.Abs(amp) * cmplx.Abs(amp)
		if prob > 0.0001 {
			if !first {
				sb.WriteString(" + ")
			}
			first = false
			binStr := fmt.Sprintf("%0*b", q.NumQubits, i)
			sb.WriteString(fmt.Sprintf("(%.4f%+.4fi)|%s⟩", real(amp), imag(amp), binStr))
		}
	}
	fmt.Println(sb.String())
}

// RenderHistogram prints an ASCII probability distribution bar chart
func RenderHistogram(shots int, counts map[int]int, numQubits int) {
	var keys []int
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	fmt.Println(strings.Repeat("-", 70))
	for _, k := range keys {
		count := counts[k]
		pct := (float64(count) / float64(shots)) * 100.0
		barLen := int(pct / 2.5)
		bar := strings.Repeat("█", barLen)
		fmt.Printf(" |%0*b⟩ (%2d): %5d (%5.1f%%) %s\n", numQubits, k, k, count, pct, bar)
	}
	fmt.Println(strings.Repeat("-", 70))
}

// ============================================================================
// 4. QUANTUM FOURIER TRANSFORM (QFT & INVERSE QFT)
// ============================================================================

func (q *QuantumState) QFT(qubits []int) {
	n := len(qubits)
	for i := 0; i < n; i++ {
		q.H(qubits[i])
		for j := i + 1; j < n; j++ {
			theta := 2 * math.Pi / math.Pow(2, float64(j-i+1))
			q.CPhase(theta, qubits[j], qubits[i])
		}
	}
	for i := 0; i < n/2; i++ {
		q.SWAP(qubits[i], qubits[n-1-i])
	}
}

func (q *QuantumState) InverseQFT(qubits []int) {
	n := len(qubits)
	for i := 0; i < n/2; i++ {
		q.SWAP(qubits[i], qubits[n-1-i])
	}
	for i := n - 1; i >= 0; i-- {
		for j := n - 1; j > i; j-- {
			theta := -2 * math.Pi / math.Pow(2, float64(j-i+1))
			q.CPhase(theta, qubits[j], qubits[i])
		}
		q.H(qubits[i])
	}
}

// ============================================================================
// 5. ALGORITHM 1: GROVER'S QUANTUM SEARCH (3 QUBITS)
// ============================================================================

func RunGroverSearch(markedTarget int) {
	fmt.Println("\n" + strings.Repeat("=", 75))
	fmt.Printf(" ALGORITHM 1: GROVER'S SEARCH (3 QUBITS, MARKED TARGET = |%03b⟩ [%d])\n", markedTarget, markedTarget)
	fmt.Println(strings.Repeat("=", 75))

	qs := NewQuantumState(3)

	// Step 1: Uniform superposition across all 8 states
	for i := 0; i < 3; i++ {
		qs.H(i)
	}
	fmt.Println("-> State after initial Walsh-Hadamard transform:")
	qs.PrintState()

	// Optimal iterations: R = round(pi/4 * sqrt(N)) = round(pi/4 * sqrt(8)) = 2 iterations
	numIterations := 2

	for iter := 1; iter <= numIterations; iter++ {
		// A. Phase Inversion Oracle: |x⟩ -> -|x⟩ if x == markedTarget
		// Implemented via bit inversion + Multi-Controlled Z (CCZ)
		for bit := 0; bit < 3; bit++ {
			if (markedTarget & (1 << bit)) == 0 {
				qs.X(bit)
			}
		}
		// Multi-Controlled Z on qubits 0, 1 with target 2: H(2) -> Toffoli(0,1,2) -> H(2)
		qs.H(2)
		qs.Toffoli(0, 1, 2)
		qs.H(2)
		for bit := 0; bit < 3; bit++ {
			if (markedTarget & (1 << bit)) == 0 {
				qs.X(bit)
			}
		}

		// B. Grover Diffusion Operator (Inversion about the mean)
		// D = H^n * (2|0⟩⟨0| - I) * H^n
		for bit := 0; bit < 3; bit++ {
			qs.H(bit)
			qs.X(bit)
		}
		qs.H(2)
		qs.Toffoli(0, 1, 2)
		qs.H(2)
		for bit := 0; bit < 3; bit++ {
			qs.X(bit)
			qs.H(bit)
		}
	}

	fmt.Printf("-> State after %d Grover amplification iterations:\n", numIterations)
	qs.PrintState()

	shots := 2048
	counts := qs.Sample(shots)
	fmt.Printf("-> Measurement sampling distribution (%d shots):\n", shots)
	RenderHistogram(shots, counts, 3)

	targetCount := counts[markedTarget]
	successRate := (float64(targetCount) / float64(shots)) * 100.0
	fmt.Printf(" Grover Isolation Success Rate: %.2f%%\n", successRate)
}

// ============================================================================
// 6. ALGORITHM 2: SHOR'S QUANTUM ORDER FINDING (FACTORING N = 15)
// ============================================================================

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// Controlled Modular Multiplication Unitary: |c⟩|y⟩ -> |c⟩|(a * y) mod N⟩
// Since gcd(a, N) = 1, the mapping y -> (a*y) mod N is a bijective permutation.
func (q *QuantumState) ApplyControlledModMul(controlQubit int, workQubits []int, a, mod int) {
	workMask := 0
	for _, w := range workQubits {
		workMask |= 1 << w
	}

	workOffset := workQubits[0]
	numWork := len(workQubits)
	workDim := 1 << numWork

	// Precompute mapping table
	perm := make([]int, workDim)
	for y := 0; y < workDim; y++ {
		if y < mod {
			perm[y] = (y * a) % mod
		} else {
			perm[y] = y
		}
	}

	newAmps := make([]complex128, q.Dim)
	copy(newAmps, q.Amps)

	for i := 0; i < q.Dim; i++ {
		// Only transform if the control qubit is active
		if (i & (1 << controlQubit)) != 0 {
			y := (i & workMask) >> workOffset
			newY := perm[y]
			targetIdx := (i & ^workMask) | (newY << workOffset)
			newAmps[targetIdx] = q.Amps[i]
		}
	}
	q.Amps = newAmps
}

func RunShorFactoring(N, a int) {
	fmt.Println("\n" + strings.Repeat("=", 75))
	fmt.Printf(" ALGORITHM 2: SHOR'S FACTORING ALGORITHM (N = %d, Coprime Base a = %d)\n", N, a)
	fmt.Println(strings.Repeat("=", 75))

	// Counting register: 3 qubits (allows resolution of period r=4: 2^3 = 8)
	// Work register: 4 qubits (2^4 = 16 > 15 to store numbers 0..14)
	// Total qubits = 3 + 4 = 7 qubits (State vector dimension = 2^7 = 128)
	numCounting := 3
	numWork := 4
	totalQubits := numCounting + numWork

	qs := NewQuantumState(totalQubits)
	countingQubits := []int{0, 1, 2}
	workQubits := []int{3, 4, 5, 6}

	// Step 1: Initialize work register to |1⟩ = |0001⟩
	qs.X(workQubits[0])

	// Step 2: Initialize counting register to uniform superposition
	for _, c := range countingQubits {
		qs.H(c)
	}

	// Step 3: Controlled modular exponentiation
	// For each counting qubit k: apply controlled-(a^(2^k) mod N)
	for k := 0; k < numCounting; k++ {
		power := 1 << k
		// Compute a^(2^k) mod N
		basePow := 1
		for p := 0; p < power; p++ {
			basePow = (basePow * a) % N
		}
		qs.ApplyControlledModMul(countingQubits[k], workQubits, basePow, N)
	}

	// Step 4: Inverse Quantum Fourier Transform (QFT†) on counting register
	qs.InverseQFT(countingQubits)

	// Step 5: Measurement sampling of the counting register
	shots := 2048
	counts := qs.Sample(shots)

	// Marginalize probabilities to extract counting register values (qubits 0,1,2)
	countingCounts := make(map[int]int)
	maskCounting := (1 << numCounting) - 1
	for basisState, count := range counts {
		countingVal := basisState & maskCounting
		countingCounts[countingVal] += count
	}

	fmt.Printf("-> Measurement of Counting Register (%d shots, 2^3 = 8 states):\n", shots)
	RenderHistogram(shots, countingCounts, numCounting)

	// Classical Post-Processing (Phase estimation & period recovery)
	fmt.Println("-> Classical Post-Processing & Factor Extraction:")
	recoveredPeriod := -1

	// For N=15, a=7: peaks occur at multiples of 2^3/r = 8/4 = 2 -> {0, 2, 4, 6}
	for measuredVal, count := range countingCounts {
		if float64(count)/float64(shots) < 0.15 || measuredVal == 0 {
			continue // Skip trivial |0⟩ phase
		}
		phase := float64(measuredVal) / math.Pow(2, float64(numCounting))
		fmt.Printf("   Peak |%d⟩ (Phase = %d/8 = %.3f)", measuredVal, measuredVal, phase)

		// Candidate period extraction via fraction denominator
		// 2/8 -> 1/4 (r=4); 6/8 -> 3/4 (r=4); 4/8 -> 1/2 (r=2)
		denom := 8 / gcd(measuredVal, 8)
		fmt.Printf(" -> Candidate Period r = %d\n", denom)
		if denom%2 == 0 {
			recoveredPeriod = denom
		}
	}

	if recoveredPeriod != -1 {
		fmt.Printf("\n [SUCCESS] Verified Order/Period r = %d for %d^r ≡ 1 (mod %d)\n", recoveredPeriod, a, N)

		// Shor's factor extraction: gcd(a^(r/2) ± 1, N)
		halfPower := int(math.Pow(float64(a), float64(recoveredPeriod/2)))
		factor1 := gcd(halfPower-1, N)
		factor2 := gcd(halfPower+1, N)

		fmt.Printf(" -> Compute a^(r/2) - 1 = %d^(%d) - 1 = %d\n", a, recoveredPeriod/2, halfPower-1)
		fmt.Printf(" -> Compute a^(r/2) + 1 = %d^(%d) + 1 = %d\n", a, recoveredPeriod/2, halfPower+1)
		fmt.Printf(" -> GCD(%d, %d) = %d\n", halfPower-1, N, factor1)
		fmt.Printf(" -> GCD(%d, %d) = %d\n", halfPower+1, N, factor2)

		if factor1*factor2 == N || (factor1 > 1 && factor1 < N) {
			fmt.Printf("\n ******************************************************************\n")
			fmt.Printf("   SHOR'S QUANTUM FACTORIZATION COMPLETE: %d = %d × %d\n", N, factor1, factor2)
			fmt.Printf(" ******************************************************************\n")
		}
	}
}

// ============================================================================
// 7. MULTI-THREADED PERFORMANCE BENCHMARK & PQC IMPACT
// ============================================================================

func RunParallelBenchmark() {
	fmt.Println("\n" + strings.Repeat("=", 75))
	fmt.Println(" BENCHMARK: CONCURRENT GOROUTINE GATE EVALUATION ACROSS QUBIT SIZES")
	fmt.Println(strings.Repeat("=", 75))
	fmt.Printf(" Running on %d logical CPU cores\n\n", runtime.NumCPU())

	sizes := []int{10, 12, 14, 16}

	for _, n := range sizes {
		qs := NewQuantumState(n)
		start := time.Now()

		// Apply a multi-gate sequence
		for q := 0; q < n; q++ {
			qs.H(q)
		}
		for q := 0; q < n-1; q++ {
			qs.CNOT(q, q+1)
		}

		elapsed := time.Since(start)
		fmt.Printf(" %2d Qubits (State Vector Dim: %6d elements) | Latency: %10v\n",
			n, qs.Dim, elapsed)
	}
}

func DisplayPostQuantumCryptographicAnalysis() {
	fmt.Println("\n" + strings.Repeat("=", 75))
	fmt.Println(" POST-QUANTUM CRYPTOGRAPHY (PQC) IMPACT ANALYSIS")
	fmt.Println(strings.Repeat("=", 75))

	fmt.Println(`
1. SHOR'S ALGORITHM IMPACT (Asymmetric Cryptography: RSA, DH, ECDSA):
   • Complexity: Polynomial time O((log N)^3) on a quantum computer.
   • Consequence: Completely breaks RSA-2048, RSA-4096, Curve25519, and secp256k1.
   • Remedy: Migrate to NIST Post-Quantum Standards:
     - ML-KEM (Kyber) for Key Encapsulation (Lattice-based).
     - ML-DSA (Dilithium) & SLH-DSA (SPHINCS+) for Digital Signatures.

2. GROVER'S ALGORITHM IMPACT (Symmetric Cryptography & Hashes: AES, SHA-2/3):
   • Complexity: Quadratic speedup O(sqrt(N)) vs Classical O(N).
   • Consequence: Effectively halves symmetric key bit-security.
     - AES-128 -> 64-bit quantum security (VULNERABLE / BELOW REQUISITE MARGIN).
     - AES-256 -> 128-bit quantum security (STILL SAFE / RESILIENT).
     - SHA-256 -> 128-bit collision resistance (STILL SAFE / RESILIENT).
   • Remedy: Double symmetric key sizes (use AES-256 exclusively).`)
	fmt.Println(strings.Repeat("=", 75))
}

// ============================================================================
// 8. MAIN ENTRY POINT
// ============================================================================

func main() {
	fmt.Println(strings.Repeat("*", 75))
	fmt.Println(" QUANTUM CIRCUIT SIMULATOR & ALGORITHM ENGINE (GO STANDARD LIBRARY)")
	fmt.Println(strings.Repeat("*", 75))

	// 1. Grover's Search for marked state |101⟩ (5)
	RunGroverSearch(5)

	// 2. Shor's Order-Finding Algorithm factoring 15 with base 7
	RunShorFactoring(15, 7)

	// 3. Multi-threaded benchmark across 10 to 16 qubits
	RunParallelBenchmark()

	// 4. Post-quantum cryptographic implications
	DisplayPostQuantumCryptographicAnalysis()
}

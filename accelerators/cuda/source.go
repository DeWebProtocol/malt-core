package cuda

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed worker/kzg.cu worker/headers.json
var assets embed.FS

// Compile only pinned arithmetic. These kernels do not use ICICLE's MSM API.
// Omit host-only stream/random/hash helpers when assembling NVRTC source.
func mathSource(include string) (string, error) {
	manifest, _ := assets.ReadFile("worker/headers.json")
	var hashes map[string]string
	if err := json.Unmarshal(manifest, &hashes); err != nil {
		return "", err
	}
	files := make(map[string]string, len(hashes))
	directives := regexp.MustCompile(`(?m)^\s*#\s*(?:include\b.*|pragma once)\s*$`)
	for name, hash := range hashes {
		data, err := os.ReadFile(filepath.Join(include, filepath.FromSlash(name)))
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != hash {
			return "", fmt.Errorf("ICICLE v2.8.0 header mismatch: %s (preserve LF line endings)", name)
		}
		files[name] = directives.ReplaceAllString(string(data), "")
	}
	strip := func(name string, markers ...string) error {
		for _, marker := range markers {
			var err error
			files[name], err = withoutFunction(files[name], marker)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := strip("fields/field.cuh", "  static HOST_INLINE Field rand_host()", "  static void rand_host_many", "  friend std::ostream& operator<<"); err != nil {
		return "", err
	}
	field := files["fields/field.cuh"]
	start := strings.Index(field, "template <class CONFIG>\nstruct std::hash")
	end := strings.Index(field, "template <class CONFIG>\nstruct SharedMemory")
	if start < 0 || end <= start {
		return "", fmt.Errorf("missing ICICLE host hash helper")
	}
	files["fields/field.cuh"] = field[:start] + field[end:]
	if err := strip("curves/affine.cuh", "  friend HOST_INLINE std::ostream&"); err != nil {
		return "", err
	}
	if err := strip("curves/projective.cuh", "  friend HOST_INLINE std::ostream&", "  static HOST_INLINE Projective rand_host()", "  static void rand_host_many(", "  static void rand_host_many_affine("); err != nil {
		return "", err
	}
	files["fields/host_math.cuh"] = strings.ReplaceAll(files["fields/host_math.cuh"], "__host__", "__device__")
	parts := []string{`typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef int int32_t;
typedef long long int64_t;
#define HOST_INLINE __device__ __forceinline__
#define DEVICE_INLINE __device__ __forceinline__
#define HOST_DEVICE_INLINE __device__ __forceinline__
#define UNROLL _Pragma("unroll")
#define THROW_ICICLE_ERR(...) asm("trap;")
#define UINT32_MAX 0xffffffffu
template<class T> struct SharedMemory;`}
	for _, name := range []string{"fields/storage.cuh", "fields/ptx.cuh", "fields/host_math.cuh", "fields/params_gen.cuh", "fields/field.cuh", "fields/snark_fields/bls12_381_base.cuh", "fields/snark_fields/bls12_381_scalar.cuh", "curves/affine.cuh", "curves/projective.cuh"} {
		parts = append(parts, files[name])
	}
	parts = append(parts, `using F = Field<bls12_381::fq_config>;
using S = Field<bls12_381::fp_config>;
static constexpr F curve_b = F::from(4);
static constexpr F unused_gx = F::from(0);
static constexpr F unused_gy = F::from(0);
using Point = Projective<F, S, curve_b, unused_gx, unused_gy>;`)
	kernel, _ := assets.ReadFile("worker/kzg.cu")
	parts = append(parts, string(kernel))
	return strings.Join(parts, "\n"), nil
}

func withoutFunction(text, marker string) (string, error) {
	start := strings.Index(text, marker)
	if start < 0 {
		return "", fmt.Errorf("missing ICICLE helper %q", marker)
	}
	offset := strings.IndexByte(text[start:], '{')
	if offset < 0 {
		return "", fmt.Errorf("missing ICICLE helper body")
	}
	end := start + offset + 1
	depth := 1
	for ; end < len(text) && depth > 0; end++ {
		if text[end] == '{' {
			depth++
		}
		if text[end] == '}' {
			depth--
		}
	}
	if depth != 0 {
		return "", fmt.Errorf("unterminated ICICLE helper")
	}
	return text[:start] + text[end:], nil
}

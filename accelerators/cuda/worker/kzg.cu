// Experimental scheduling around ICICLE's unmodified BLS12-381 field/point math.
// The fixed-base table shifts each SRS point by window bits, not by a query.
extern "C" __global__ void kzg_precompute(const Affine<F>* bases, Point* table,
                                           int n, int width, int windows) {
  int i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) return;
  Point p = Point::from_affine(bases[i]);
  for (int w = 0; w < windows; w++) {
    table[w*n+i] = p;
    for (int k = 0; k < width; k++) p = Point::dbl(p);
  }
}

__device__ __forceinline__ unsigned rev12(unsigned v) { return __brev(v) >> 20; }

extern "C" __global__ void kzg_quotient(const S* vector, const S* roots,
    const S* differences, const int* indices, S* q, S* contributions, int batch) {
  int tid = blockIdx.x * blockDim.x + threadIdx.x;
  if (tid >= batch*4096) return;
  int b = tid / 4096, j = tid % 4096, index = indices[b];
  if (j == index) { q[tid] = S::zero(); contributions[tid] = S::zero(); return; }
  unsigned zi = rev12(index), d = (rev12(j) - zi) & 4095;
  S qj = (vector[b*4096+j] - vector[b*4096+index]) * differences[d] * roots[(-zi)&4095];
  q[tid] = qj;
  contributions[tid] = S::neg(qj * roots[d]);
}

extern "C" __global__ void kzg_quotient_diagonal(S* q, const S* contributions, const int* indices) {
  __shared__ S sums[256];
  int t = threadIdx.x, b = blockIdx.x;
  S acc = S::zero();
  for (int j = t; j < 4096; j += 256) acc = acc + contributions[b*4096+j];
  sums[t] = acc; __syncthreads();
  for (int d = 128; d > 0; d >>= 1) {
    if (t < d) sums[t] = sums[t] + sums[t+d];
    __syncthreads();
  }
  if (t == 0) q[b*4096+indices[b]] = sums[0];
}

extern "C" __global__ void kzg_buckets(const Point* table, const S* scalars,
    Point* partial, int n, int chunk_size, int width, int windows, int batch) {
  int chunks = (n + chunk_size - 1) / chunk_size;
  int buckets = (1 << width) - 1;
  int count = chunks * windows * buckets;
  int id = blockIdx.x * blockDim.x + threadIdx.x;
  if (id >= batch * count) return;
  int b = id/count, local = id%count;
  int digit = local%buckets+1, c = (local/buckets)%chunks, w = local/(buckets*chunks);
  Point acc = Point::zero();
  bool used = false;
  int end = min(n,(c+1)*chunk_size);
  for (int i = c*chunk_size; i < end; i++) {
    if (scalars[b*n+i].get_scalar_digit(w,width) == digit) {
      acc = used ? acc + table[w*n+i] : table[w*n+i];
      used = true;
    }
  }
  Point weighted = Point::zero();
  bool added = false;
  if (used) {
    for (int bit = width-1; bit >= 0; bit--) {
      if (added) weighted = Point::dbl(weighted);
      if ((digit >> bit) & 1) { weighted = added ? weighted+acc : acc; added = true; }
    }
  }
  partial[id] = weighted;
}

extern "C" __global__ void kzg_reduce(const Point* src, Point* dst, int n) {
  __shared__ Point sums[128];
  int b = blockIdx.y, group = blockIdx.x, t = threadIdx.x;
  int i = group*128+t, groups = (n+127)/128;
  sums[t] = i<n ? src[b*n+i] : Point::zero();
  __syncthreads();
  for (int d=64; d>0; d>>=1) {
    if (t<d) sums[t] = sums[t]+sums[t+d];
    __syncthreads();
  }
  if (t==0) dst[b*groups+group]=sums[0];
}

extern "C" __global__ void kzg_normalize(const Point* src, Affine<F>* dst, int batch) {
  int i=blockIdx.x*blockDim.x+threadIdx.x;
  if (i<batch) dst[i]=Point::to_affine(src[i]);
}

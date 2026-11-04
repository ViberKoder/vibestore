export function shannonEntropy(buf: Buffer): number {
  if (buf.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (let i = 0; i < buf.length; i++) counts[buf[i]]++;
  let entropy = 0;
  const len = buf.length;
  for (const c of counts) {
    if (!c) continue;
    const p = c / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function sampleEntropy(buf: Buffer, maxBytes = 256_000): number {
  if (buf.length <= maxBytes) return shannonEntropy(buf);
  const step = Math.floor(buf.length / maxBytes);
  const sample = Buffer.alloc(maxBytes);
  for (let i = 0; i < maxBytes; i++) sample[i] = buf[i * step];
  return shannonEntropy(sample);
}

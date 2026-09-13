declare module 'bencode' {
  const b: { encode(v: unknown): Buffer; decode(b: Buffer): any };
  export default b;
}

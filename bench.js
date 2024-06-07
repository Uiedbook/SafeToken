import { SafeToken } from "./dist/index.js";

// auth
const Auth = new SafeToken({
  secret: "9494d249ad9fd041f9d052e0d0b9c9e7e45bfc3f",
});

export async function benchSuit(code, runs = 1_000_000, label) {
  const startTime = performance.now();
  for (let i = 0; i < runs; i++) {
    await code();
  }
  let totalTime = performance.now() - startTime;
  if (label) {
    console.log(label + " - Bechmark score");
  }
  console.log(
    `Code took ${totalTime} ms on ${runs} runs with an average of ${
      totalTime / runs
    } ms per operation`
  );
  console.log("");
  return totalTime;
}

await benchSuit(async () => {
  await Auth.verify(await Auth.create());
});

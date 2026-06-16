import type { Metadata } from "next";
import { Playground } from "@/components/playground";

export const metadata: Metadata = {
  title: "Playground — Aegis",
  description:
    "Run the Aegis policy engine yourself: compose a tool call and a trajectory, see the live allow/deny verdict and the rule that fired.",
};

export default function PlaygroundPage() {
  return (
    <main className="relative flex-1 overflow-x-clip">
      <Playground />
    </main>
  );
}

import path from "node:path";

export function preview(name: string) {
  return <img src={path.join("/uploads", path.basename(name))} />;
}

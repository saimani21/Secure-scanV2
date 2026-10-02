import path from "node:path";

export function preview(req: any) {
  return <img src={path.join("/uploads", req.params.name)} />;
}

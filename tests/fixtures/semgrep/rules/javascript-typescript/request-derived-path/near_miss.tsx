export function preview(pathBuilder: any, req: any) {
  return <img src={pathBuilder.join("/uploads", req.params.name)} />;
}

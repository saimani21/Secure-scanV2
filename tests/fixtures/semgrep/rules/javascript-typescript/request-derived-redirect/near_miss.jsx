export function redirect(request, response) {
  const target = request.query.next;
  return response.redirect(target);
}

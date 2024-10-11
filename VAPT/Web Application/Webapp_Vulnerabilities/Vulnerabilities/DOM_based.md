# DOM Based Open Redirection

DOM-based open-redirection vulnerabilities arise when a script writes attacker-controllable data into a sink that can trigger cross-domain navigation. For example, the following code is vulnerable due to the unsafe way it handles the location.hash property:

let url = /https?:\/\/.+/.exec(location.hash);
if (url) {
  location = url[0];
}
An attacker may be able to use this vulnerability to construct a URL that, if visited by another user, will cause a redirection to an arbitrary external domain.



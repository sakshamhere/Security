https://developer.mozilla.org/en-US/docs/Web/API/Window#instance_properties

A global variable, `window`, representing the window in which the script is running, is exposed to JavaScript code.

The `Window` represents a window containing a DOM document; the document property points to the DOM document loaded in that window.

In a tabbed browser, each tab is represented by its own `Window` object.


So basically all those variables we aceess like document, location etc all are child to window object.

examples

`Window.location`

    Gets/sets the location, or current URL, of the window object.


`Window.document` 

    Returns a reference to the document that the window contains.

`Window.frames` 

    Returns an array of the subframes in the current window.

`Window.opener`

    Returns a reference to the window that opened this current window.

`Window.top`

    refers to the top-most window from a window nested in one or more layers of <iframe> sub-windows

`window.parent` 

    refers to the parent of a window in a <frame> or <iframe>

COMPLETE LIST -> https://developer.mozilla.org/en-US/docs/Web/API/Window
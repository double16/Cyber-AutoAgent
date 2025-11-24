import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

// Minimal ESM-compatible mock of ink-testing-library that renders the Ink
// component tree (mocked by tests/unit/mocks/ink.js) to static HTML and
// exposes a lastFrame() helper that returns the current markup string.

export const render = (node) => {
  let currentNode = node;
  return {
    lastFrame: () => (currentNode ? renderToStaticMarkup(currentNode) : ''),
    rerender: (next) => {
      currentNode = next;
    },
    unmount: () => {
      currentNode = null;
    },
  };
};

export default { render };

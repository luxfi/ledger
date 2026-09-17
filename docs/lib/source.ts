import { docs } from "@/.source"
import { loader } from "fumadocs-core/source"

// Create a single source instance that is reused
// This prevents circular references and stack overflow issues
// The wrapper is what keeps the TYPE. `loader` is generic, so annotating the
// cache with ReturnType<typeof loader> instantiates it with no type arguments
// and collapses the page data to its base — which is why body, toc and full
// were all reported as missing while fumadocs exported them the whole time. A
// wrapper's return type is the INSTANTIATED generic, so the concrete page data
// survives and the memo below still does its job.
function createSource() {
  return loader({
    baseUrl: "/docs",
    source: docs.toFumadocsSource(),
  })
}

let _source: ReturnType<typeof createSource> | null = null

export function getSource() {
  if (!_source) {
    _source = createSource()
  }
  return _source
}

export const source = getSource()

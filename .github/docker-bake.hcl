# Release build of the self-built images (.github/workflows/release.yml), on top of compose.yaml (contexts, the pinned
# python base, build args and the image names ghcr.io/c-ardinal/geofront-nw-<svc>:${GEOFRONT_VERSION} come from there):
#   GEOFRONT_VERSION=v1.2.3 docker buildx bake -f compose.yaml -f .github/docker-bake.hcl release [--push]
# Every Dockerfile runs its selftest during the build (per platform), so a failing selftest fails the build.
variable "PLATFORMS" {
  default = "linux/amd64,linux/arm64"
}

group "release" {
  targets = ["tools", "mask-api", "analyzer", "flowd", "notify-relay", "demo-gen", "capture"]
}

target "_release" {
  platforms = split(",", PLATFORMS)
  labels = {
    "org.opencontainers.image.source"   = "https://github.com/c-ardinal/GeoFront-NW"
    "org.opencontainers.image.licenses" = "MIT"
  }
}

target "tools" { inherits = ["_release"] }
target "mask-api" {
  inherits = ["_release"]
  args = { SELFTEST_EVIDENCE_BUDGET = "900" }  # slower arm64 runner: the evidence selftest's exports need longer
}
target "analyzer" { inherits = ["_release"] }
target "flowd" { inherits = ["_release"] }
target "notify-relay" { inherits = ["_release"] }
target "demo-gen" { inherits = ["_release"] }
target "capture" { inherits = ["_release"] }

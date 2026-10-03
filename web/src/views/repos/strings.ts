// SPDX-License-Identifier: Apache-2.0

// Every user-visible string of the repositories index.

export const strings = {
  labels: {
    title: "Repositories",
    repository: "Repository",
    lastActivity: "Last activity",
    runs: "Runs",
    commits: "Commits",
    noRepos: "No repositories yet",
  },

  nouns: {
    repos: "the repositories",
  },

  sentences: {
    intro: "Every repository an agent has worked in, most recently active first.",
    empty: "No run has recorded a repository yet.",
  },
} as const;

export type ReposStrings = typeof strings;

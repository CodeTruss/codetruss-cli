import { indexWorkingTree } from '@codetruss/analyzer-engine/indexer'
import { excludeMatcher } from './policy.js'

/** Keep hosted historical classification stable while making local evidence binary-aware. */
export function indexRepository(root: string, exclude: string[] = []) {
  return indexWorkingTree(root, { assetMode: 'binary-aware', exclude: excludeMatcher(exclude) })
}

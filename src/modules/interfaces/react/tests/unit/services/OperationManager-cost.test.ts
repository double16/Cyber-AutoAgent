/**
 * OperationManager cost calculation tests across pricing matrices
 */
import { describe, it, expect } from '@jest/globals';
import { OperationManager } from '../../../src/services/OperationManager.js';
import type { Config } from '../../../src/contexts/ConfigContext.js';

describe('OperationManager cost calculation', () => {
  const baseConfig: Config = {
    // minimal viable config
    modelProvider: 'bedrock',
    modelId: 'us.anthropic.claude-sonnet-4-20250514-v1:0',
    awsRegion: 'us-east-1',
    dockerImage: 'image',
    dockerTimeout: 300,
    volumes: [],
    iterations: 10,
    autoApprove: true,
    confirmations: false,
    maxThreads: 5,
    outputFormat: 'markdown',
    verbose: false,
    memoryMode: 'auto',
    keepMemory: true,
    memoryBackend: 'FAISS',
    outputDir: './outputs',
    unifiedOutput: true,
    theme: 'retro',
    showMemoryUsage: false,
    showOperationId: true,
    environment: {},
    reportSettings: { includeRemediation: true, includeCWE: true, includeTimestamps: true, includeEvidence: true, includeMemoryOps: true },
    observability: false,
    isConfigured: true,
    allowExecutionFallback: true,
    modelPricing: {
      'us.anthropic.claude-sonnet-4-20250514-v1:0': { inputCostPer1k: 0.006, outputCostPer1k: 0.03 },
      'claude-3-haiku-20240307-v1:0': { inputCostPer1k: 0.00025, outputCostPer1k: 0.00125 },
      'llama3.2:3b': { inputCostPer1k: 0, outputCostPer1k: 0 }, // local free
    },
  } as any;

  it('accepts estimatedCost from cost metric', () => {
    const om = new OperationManager(baseConfig);
    const op = om.startOperation('web', 'example.com', 'assessment', 'us.anthropic.claude-sonnet-4-20250514-v1:0');

    om.updateTokenUsage(op.id, 2000, 1000, 0.042); // 2k input, 1k output
    const updated = om.getOperation(op.id)!;
    expect(Number(updated.cost.estimatedCost.toFixed(6))).toBeCloseTo(0.042, 6);
  });
});

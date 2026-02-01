/**
 * Module Context for Cyber-AutoAgent
 * Manages security modules and their capabilities
 */

import React, { createContext, useContext, useState, useCallback, useEffect, useMemo } from 'react';
import * as fs from 'fs/promises';
import type { Dirent } from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { loggingService } from '../services/LoggingService.js';

const getModuleRoots = (): string[] => {
  // Default root: src/modules/operation_plugins relative to the React app cwd
  const defaultRoot = path.resolve(process.cwd(), '..', '..', 'operation_plugins');

  const raw = (process.env.CYBER_MODULE_PATH || '').trim();
  const roots: string[] = [];

  const addRoot = (p: string) => {
    let s = (p || '').trim();
    if (!s) return;

    // Expand leading ~ to HOME/USERPROFILE
    const home = process.env.HOME || process.env.USERPROFILE || '';
    if (home && (s === '~' || s.startsWith('~/'))) {
      s = s === '~' ? home : path.join(home, s.slice(2));
    }

    const resolved = path.isAbsolute(s) ? s : path.resolve(process.cwd(), s);
    if (!roots.includes(resolved)) roots.push(resolved);
  };

  for (const part of raw.split(':')) {
    addRoot(part);
  }

  // Docker module directory
  addRoot(path.resolve(process.cwd(), '..', '..', '..', '..', 'external_plugins'));

  // User module directory
  addRoot('~/.cyber-autoagent/modules');

  // Always include the built-in operation_plugins LAST
  addRoot(defaultRoot);

  return roots;
};

export interface ModuleTool {
  name: string;
  description: string;
  category: string;
}

export interface ModuleInfo {
  name: string;
  description: string;
  category: string;
  tools: ModuleTool[];
  capabilities: string[];
  reportFormat?: string;
}

export interface ModuleContextType {
  currentModule: string;
  availableModules: Record<string, ModuleInfo>;
  moduleInfo?: ModuleInfo;
  switchModule: (moduleName: string) => Promise<void>;
  suggestModuleForObjective: (objective: string) => string;
  isLoading: boolean;
  error?: string;
}

const ModuleContext = createContext<ModuleContextType | undefined>(undefined);

export const ModuleProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentModule, setCurrentModule] = useState<string>('');
  const [availableModules, setAvailableModules] = useState<Record<string, ModuleInfo>>({});
  const [moduleInfo, setModuleInfo] = useState<ModuleInfo>();
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>();

  const loadAvailableModules = useCallback(async () => {
    try {
      const moduleRoots = getModuleRoots();

      // Debug logging for module discovery
      if (process.env.DEBUG) {
        loggingService.info('[ModuleContext] Looking for modules in roots:', moduleRoots);
      }

      const modules: Record<string, ModuleInfo> = {};

      // Search roots in order; first root providing a module name wins.
      for (const root of moduleRoots) {
        try {
          await fs.access(root);
        } catch {
          // Root doesn't exist / isn't mounted; skip quietly
          continue;
        }

        let entries: Dirent[] = [];
        try {
          entries = await fs.readdir(root, { withFileTypes: true });
        } catch {
          continue;
        }

        for (const entry of entries) {
          if (!entry.isDirectory()) continue;
          if (modules[entry.name]) continue;

          const moduleInfo = await loadModuleInfo(entry.name, root);
          if (moduleInfo) {
            modules[entry.name] = moduleInfo;
          }
        }
      }

      // If no roots had modules, just set empty.
      if (Object.keys(modules).length === 0) {
        setAvailableModules({});
        return;
      }

      // PREVENT UNNECESSARY UPDATES: Check if modules actually changed
      setAvailableModules(prevModules => {
        const prevStr = JSON.stringify(prevModules);
        const newStr = JSON.stringify(modules);
        if (prevStr === newStr) {
          return prevModules; // Return same reference to prevent re-renders
        }
        return modules;
      });

      // Load default module - use first available if web doesn't exist
      const moduleNames = Object.keys(modules);
      if (moduleNames.length > 0) {
        const defaultModule = modules.web || modules[moduleNames[0]];
        const defaultModuleName = modules.web ? 'web' : moduleNames[0];
        setCurrentModule(defaultModuleName);
        setModuleInfo(defaultModule);
      }
    } catch (err) {
      // Only log in debug mode - don't show errors to users
      if (process.env.DEBUG) {
        loggingService.error('Failed to load modules:', err);
      }
      // Silently handle the error - modules are optional
      setAvailableModules({});
    }
  }, []); // Empty dependencies - only changes when component mounts

  // Load all available modules on mount
  useEffect(() => {
    loadAvailableModules();
  }, [loadAvailableModules]);

  const loadModuleInfo = async (moduleName: string, moduleRoot: string): Promise<ModuleInfo | null> => {
    try {
      const modulePath = path.join(moduleRoot, moduleName);
      const yamlPath = path.join(modulePath, 'module.yaml');
      
      // Check if module.yaml exists
      try {
        await fs.access(yamlPath);
      } catch {
        // If no YAML, create basic info
        return {
          name: moduleName,
          description: `${moduleName.replace(/_/g, ' ')} module`,
          category: 'security',
          tools: [],
          capabilities: []
        };
      }
      
      const yamlContent = await fs.readFile(yamlPath, 'utf-8');
      const moduleConfig = yaml.load(yamlContent) as any;
      
      // Load tools from tools directory
      const tools: ModuleTool[] = [];
      const toolsDir = path.join(modulePath, 'tools');
      
      try {
        const toolFiles = await fs.readdir(toolsDir);
        for (const toolFile of toolFiles) {
          if (toolFile.endsWith('.py')) {
            const toolName = toolFile.replace('.py', '');
            tools.push({
              name: toolName,
              description: moduleConfig.tools?.[toolName]?.description || toolName,
              category: moduleConfig.tools?.[toolName]?.category || 'general'
            });
          }
        }
      } catch {
        // Tools directory might not exist
      }
      
      return {
        name: moduleName,
        description: moduleConfig.description || `${moduleName} module`,
        category: moduleConfig.category || 'security',
        tools,
        capabilities: moduleConfig.capabilities || [],
        reportFormat: moduleConfig.report_format
      };
    } catch (err) {
      // Only log in debug mode
      if (process.env.DEBUG) {
        loggingService.error(`Failed to load module ${moduleName}:`, err);
      }
      return null;
    }
  };

  const switchModule = useCallback(async (moduleName: string) => {
    if (!availableModules[moduleName]) {
      setError(`Module ${moduleName} not found`);
      return;
    }
    
    setIsLoading(true);
    setError(undefined);
    
    try {
      setCurrentModule(moduleName);
      setModuleInfo(availableModules[moduleName]);
    } catch (err) {
      setError(`Failed to switch to module ${moduleName}`);
      loggingService.error(err);
    } finally {
      setIsLoading(false);
    }
  }, [availableModules]);

  const suggestModuleForObjective = useCallback((objective: string): string => {
    const objectiveLower = objective.toLowerCase();
    
    // Check each available module's capabilities and description for matches
    for (const [moduleName, moduleInfo] of Object.entries(availableModules)) {
      // Check module description
      if (moduleInfo.description.toLowerCase().includes(objectiveLower)) {
        return moduleName;
      }
      
      // Check module capabilities
      for (const capability of moduleInfo.capabilities) {
        if (objectiveLower.includes(capability.toLowerCase()) || 
            capability.toLowerCase().includes(objectiveLower)) {
          return moduleName;
        }
      }
    }
    
    // Default to web module if available, otherwise first available module
    if (availableModules.web) {
      return 'web';
    }
    
    const moduleNames = Object.keys(availableModules);
    return moduleNames.length > 0 ? moduleNames[0] : 'web';
  }, [availableModules]);

  // Use useMemo to prevent infinite re-renders
  // Without this, the value object gets recreated on every render, causing all consumers to re-render
  const value: ModuleContextType = useMemo(() => ({
    currentModule,
    availableModules,
    moduleInfo,
    switchModule,
    suggestModuleForObjective,
    isLoading,
    error
  }), [currentModule, availableModules, moduleInfo, switchModule, suggestModuleForObjective, isLoading, error]);

  return (
    <ModuleContext.Provider value={value}>
      {children}
    </ModuleContext.Provider>
  );
};

export const useModule = () => {
  const context = useContext(ModuleContext);
  if (!context) {
    throw new Error('useModule must be used within ModuleProvider');
  }
  return context;
};
import { Express } from 'express';
import { tonProofRoutes } from './tonProofRoutes';
import { dappRoutes } from './dappRoutes';
import { publicApiRoutes } from './publicApiRoutes';
import { sessionRoutes } from './sessionRoutes';
import { adminRoutes } from './adminRoutes';

export function setupRoutes(app: Express) {
  // TON Proof routes
  tonProofRoutes(app);
  
  // DApp protected routes
  dappRoutes(app);
  
  // Public API routes
  publicApiRoutes(app);
  
  // Session routes
  sessionRoutes(app);
  
  // Admin routes
  adminRoutes(app);
}
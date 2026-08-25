import { secureFetch } from '@/helpers/login';
import { fetchApi } from '@/helpers/api';
import { API_V1_BASE_URL } from '../constants';
import type {
  ExternalIssuer,
  ExternalIssuerDryRun,
  ExternalIssuerProbe,
  IssuerClient,
} from './types';

// Trusted external issuers are defined in configuration, so this surface is
// read-only: list what is configured, and the probe/dry-run diagnostics. The
// one mutable piece is the per-client blessing (clients live in the database).
const base = (namespace: string) =>
  `${API_V1_BASE_URL}/issuer/admin/ns${namespace}/external-issuers`;

const json = { 'Content-Type': 'application/json' };

const ExternalIssuerService = {
  // Which namespaces have an issuer at all. Depends on which exports need
  // authentication, so it is not derivable from a single config value.
  getNamespaces: async (): Promise<string[]> => {
    const r = await fetchApi(() =>
      secureFetch(`${API_V1_BASE_URL}/issuer/admin/namespaces`)
    );
    return await r.json();
  },
  getAll: async (namespace: string): Promise<ExternalIssuer[]> => {
    const r = await fetchApi(() => secureFetch(base(namespace)));
    return await r.json();
  },
  // probe and dryRun address the issuer by its configured name and report
  // failure in the body (ok:false) rather than as an HTTP error.
  probe: async (
    namespace: string,
    name: string
  ): Promise<ExternalIssuerProbe> => {
    const r = await fetchApi(() =>
      secureFetch(`${base(namespace)}/${name}/probe`, {
        method: 'POST',
        body: '{}',
        headers: json,
      })
    );
    return await r.json();
  },
  dryRun: async (
    namespace: string,
    name: string,
    subjectToken: string,
    clientId?: string
  ): Promise<ExternalIssuerDryRun> => {
    const r = await fetchApi(() =>
      secureFetch(`${base(namespace)}/${name}/dry-run`, {
        method: 'POST',
        body: JSON.stringify({
          subject_token: subjectToken,
          ...(clientId ? { client_id: clientId } : {}),
        }),
        headers: json,
      })
    );
    return await r.json();
  },
  listClients: async (namespace: string): Promise<IssuerClient[]> => {
    const r = await fetchApi(() =>
      secureFetch(`${API_V1_BASE_URL}/issuer/admin/ns${namespace}/clients`)
    );
    return await r.json();
  },
  // Bless or revoke a client's ability to exchange tokens from the namespace's
  // configured external issuers (all-or-none).
  setClientAllowExternalExchange: async (
    namespace: string,
    clientId: string,
    allow: boolean
  ): Promise<IssuerClient> => {
    const r = await fetchApi(() =>
      secureFetch(
        `${API_V1_BASE_URL}/issuer/admin/ns${namespace}/clients/${clientId}`,
        {
          method: 'PUT',
          body: JSON.stringify({ allow_external_token_exchange: allow }),
          headers: json,
        }
      )
    );
    return await r.json();
  },
} as const;

export default ExternalIssuerService;

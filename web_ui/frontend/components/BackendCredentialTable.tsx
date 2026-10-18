/***************************************************************
 *
 * Copyright (C) 2026, Pelican Project, Morgridge Institute for Research
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************/

'use client';

import { getErrorMessage } from '@/helpers/util';
import { secureFetch } from '@/helpers/login';
import {
  Alert,
  Box,
  Button,
  Chip,
  Link,
  Paper,
  Skeleton,
  Tooltip,
  Typography,
} from '@mui/material';
import { CheckCircle, HourglassTop, Warning } from '@mui/icons-material';
import { ReactElement, useState } from 'react';
import useSWR from 'swr';
import { ValueLabel } from './DataExportTable';

// Mirrors backendcred.Status on the server.
export interface BackendCredential {
  id: string;
  displayName: string;
  issuer: string;
  state: 'inactive' | 'pending' | 'active' | 'error';
  message?: string;
  registrationMethod?: 'preconfigured' | 'cimd' | 'dcr';
  clientId?: string;
  scopes?: string[];
  grantedScopes?: string[];
  clientSecretExpiresAt?: string;
  userCode?: string;
  verificationUri?: string;
  verificationUriComplete?: string;
  deviceCodeExpiresAt?: string;
  accessTokenExpiresAt?: string;
  lastRefresh?: string;
  activatedBy?: string;
  activatedAt?: string;
}

const registrationLabels: Record<string, string> = {
  preconfigured: 'Configured client',
  cimd: 'Client ID metadata document (federation)',
  dcr: 'Dynamically registered client',
};

const formatTime = (t?: string) => (t ? new Date(t).toLocaleString() : '');

const PendingAuthorization = ({
  credential,
}: {
  credential: BackendCredential;
}): ReactElement => {
  const link =
    credential.verificationUriComplete || credential.verificationUri || '';
  return (
    <Alert severity='info' icon={<HourglassTop />} sx={{ mt: 2 }}>
      <Typography variant='body2'>
        Someone with access to the storage must approve this server at{' '}
        <Link href={link} target='_blank' rel='noopener noreferrer'>
          {credential.verificationUri}
        </Link>
        {credential.verificationUriComplete
          ? ' (the link already carries the code)'
          : ''}{' '}
        using the code
      </Typography>
      <Typography
        variant='h5'
        sx={{ fontFamily: 'monospace', letterSpacing: 2, my: 1 }}
      >
        {credential.userCode}
      </Typography>
      <Typography variant='caption'>
        The code expires at {formatTime(credential.deviceCodeExpiresAt)}. This
        page updates once the request is approved.
      </Typography>
    </Alert>
  );
};

const CredentialRecord = ({
  credential,
  apiBase,
  onChange,
}: {
  credential: BackendCredential;
  apiBase: string;
  onChange: () => void;
}): ReactElement => {
  const [error, setError] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);

  const call = async (method: 'POST' | 'DELETE', path: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const response = await secureFetch(apiBase + path, { method });
      if (!response.ok) {
        setError(await getErrorMessage(response));
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
      onChange();
    }
  };

  const activate = () =>
    call('POST', '/' + encodeURIComponent(credential.id) + '/activate');
  const deactivate = () => {
    if (
      window.confirm(
        'Forget this credential? The backend will be unavailable until it is activated again.'
      )
    ) {
      call('DELETE', '/' + encodeURIComponent(credential.id));
    }
  };

  const active = credential.state === 'active' || credential.state === 'error';
  return (
    <Paper elevation={3} sx={{ mb: 2, p: 2, minWidth: 600 }}>
      <Box display='flex' alignItems='center'>
        <Box flexGrow={1}>
          <Typography variant='h6'>{credential.displayName}</Typography>
          <ValueLabel label='Issuer' value={credential.issuer} />
        </Box>
        <Box ml={4} display='flex' alignItems='center' gap={1}>
          {credential.state === 'active' && (
            <Chip color='success' icon={<CheckCircle />} label='Active' />
          )}
          {credential.state === 'error' && (
            <Tooltip title={credential.message || ''}>
              <Chip
                color='warning'
                icon={<Warning />}
                label='Refresh failing'
              />
            </Tooltip>
          )}
          {credential.state === 'pending' && (
            <Chip
              color='info'
              icon={<HourglassTop />}
              label='Awaiting approval'
            />
          )}
          {credential.state === 'inactive' && (
            <Chip color='warning' icon={<Warning />} label='Not activated' />
          )}
          <Tooltip
            title={
              active
                ? 'Start a new device authorization; the current credential keeps working until it is approved'
                : 'Start the device authorization; you will be given a code to approve at the issuer'
            }
          >
            <span>
              <Button
                variant={active ? 'outlined' : 'contained'}
                color={active ? 'primary' : 'warning'}
                disabled={busy}
                onClick={activate}
              >
                {active ? 'Re-activate' : 'Activate'}
              </Button>
            </span>
          </Tooltip>
          {credential.state !== 'inactive' && (
            <Button color='error' disabled={busy} onClick={deactivate}>
              Deactivate
            </Button>
          )}
        </Box>
      </Box>

      {credential.state === 'pending' && (
        <PendingAuthorization credential={credential} />
      )}
      {credential.message && credential.state !== 'pending' && (
        <Alert
          severity={credential.state === 'active' ? 'info' : 'warning'}
          sx={{ mt: 2 }}
        >
          {credential.message}
        </Alert>
      )}
      {error && (
        <Alert severity='error' sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}

      <Box mt={2} display='flex' flexWrap='wrap' gap={2}>
        <ValueLabel
          label='OAuth client'
          value={
            credential.registrationMethod
              ? registrationLabels[credential.registrationMethod] ||
                credential.registrationMethod
              : ''
          }
        />
        <ValueLabel label='Client ID' value={credential.clientId || ''} />
        <ValueLabel
          label='Scopes'
          value={(credential.scopes || []).join(' ')}
        />
        <ValueLabel
          label='Granted scopes'
          value={(credential.grantedScopes || []).join(' ')}
        />
        <ValueLabel
          label='Client secret expires'
          value={formatTime(credential.clientSecretExpiresAt)}
        />
        <ValueLabel label='Activated by' value={credential.activatedBy || ''} />
        <ValueLabel
          label='Activated at'
          value={formatTime(credential.activatedAt)}
        />
        <ValueLabel
          label='Access token expires'
          value={formatTime(credential.accessTokenExpiresAt)}
        />
      </Box>
    </Paper>
  );
};

/**
 * Lists a server module's storage-backend credentials and lets an admin
 * activate them with the OAuth device flow.  `apiBase` is the module's
 * backend_credentials endpoint, e.g. /api/v1.0/origin_ui/backend_credentials.
 */
export const BackendCredentialTable = ({ apiBase }: { apiBase: string }) => {
  const { data, error, mutate } = useSWR<BackendCredential[]>(
    apiBase,
    async (url: string) => {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(await getErrorMessage(response));
      }
      return response.json();
    },
    {
      // Poll while a device authorization is waiting so the page notices
      // the approval.
      refreshInterval: (latest) =>
        latest?.some((c) => c.state === 'pending') ? 3000 : 0,
    }
  );

  if (error) {
    return (
      <Box p={1}>
        <Typography sx={{ color: 'red' }} variant={'subtitle2'}>
          {error.toString()}
        </Typography>
      </Box>
    );
  }
  if (!data) {
    return <Skeleton variant={'rectangular'} height={200} width={'100%'} />;
  }
  if (data.length === 0) {
    return (
      <Typography variant='body1'>
        This server holds no storage-backend credentials. They are configured
        with Origin.HttpAuthOAuth2DeviceFlow.
      </Typography>
    );
  }
  return (
    <Box>
      {data.map((credential) => (
        <CredentialRecord
          key={credential.id}
          credential={credential}
          apiBase={apiBase}
          onChange={() => mutate()}
        />
      ))}
    </Box>
  );
};

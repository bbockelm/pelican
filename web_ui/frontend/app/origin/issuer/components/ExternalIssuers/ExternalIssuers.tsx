'use client';

import React, { useContext, useMemo, useState } from 'react';
import useSWR from 'swr';
import {
  Alert,
  Box,
  Chip,
  IconButton,
  MenuItem,
  Stack,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import ScienceIcon from '@mui/icons-material/Science';
import NetworkCheckIcon from '@mui/icons-material/NetworkCheck';
import VpnKeyIcon from '@mui/icons-material/VpnKey';

import { ExternalIssuerService, type ExternalIssuer } from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';
import DryRunDialog from './DryRunDialog';
import ClientBlessingDialog from './ClientBlessingDialog';

/**
 * Read-only view of the trusted external issuers this origin will exchange
 * tokens from. Issuers are defined in configuration
 * (Origin.Exports[*].ExternalIssuers / Issuer.ExternalIssuers) — trust anchors
 * under change control — so this panel does not edit them; it shows what is
 * configured and offers the probe and dry-run diagnostics. The one thing it can
 * change is which clients are blessed for external exchange (clients live in the
 * database).
 */
const ExternalIssuers: React.FC = () => {
  const dispatch = useContext(AlertDispatchContext);
  const [namespace, setNamespace] = useState<string | undefined>();
  const [dryRunFor, setDryRunFor] = useState<ExternalIssuer | undefined>();
  const [clientsOpen, setClientsOpen] = useState(false);
  const [busy, setBusy] = useState<string | undefined>();

  const { data: namespaces } = useSWR<string[] | undefined>(
    'issuer-namespaces',
    () =>
      alertOnError(
        () => ExternalIssuerService.getNamespaces(),
        'Failed to load issuer namespaces',
        dispatch
      )
  );
  const activeNamespace = useMemo(
    () => namespace ?? namespaces?.[0],
    [namespace, namespaces]
  );

  const { data: issuers } = useSWR<ExternalIssuer[] | undefined>(
    activeNamespace ? ['external-issuers', activeNamespace] : null,
    () =>
      alertOnError(
        () => ExternalIssuerService.getAll(activeNamespace as string),
        'Failed to load external issuers',
        dispatch
      ),
    { fallbackData: [] }
  );

  const notify = (message: string, severity: 'success' | 'info' = 'info') =>
    dispatch({
      type: 'openAlert',
      payload: {
        onClose: () => dispatch({ type: 'closeAlert' }),
        message,
        autoHideDuration: 5000,
        alertProps: { severity },
      },
    });

  const probe = async (issuer: ExternalIssuer) => {
    if (!activeNamespace) return;
    setBusy(issuer.name);
    try {
      const r = await alertOnError(
        () => ExternalIssuerService.probe(activeNamespace, issuer.name),
        'Probe failed',
        dispatch,
        true
      );
      if (r?.ok) {
        notify(
          `${issuer.name}: ${r.key_count} key(s) from ${r.jwks_url}` +
            (r.algorithms?.length ? ` (${r.algorithms.join(', ')})` : ''),
          'success'
        );
      } else {
        notify(`${issuer.name}: ${r?.error}`);
      }
    } catch {
      /* alertOnError already reported it */
    }
    setBusy(undefined);
  };

  if (namespaces && namespaces.length === 0) {
    return (
      <Alert severity='info'>
        No namespace on this origin has an embedded issuer, so there is nothing
        to exchange tokens for.
      </Alert>
    );
  }

  return (
    <Box>
      <Box
        display='flex'
        alignItems='center'
        justifyContent='space-between'
        flexWrap='wrap'
        gap={1}
        sx={{ mb: 1 }}
      >
        <Typography variant='h5'>Trusted external issuers</Typography>
        <Tooltip title='Choose which clients may use these issuers'>
          <span>
            <IconButton
              size='small'
              disabled={!activeNamespace}
              onClick={() => setClientsOpen(true)}
              aria-label='Clients allowed to use external issuers'
            >
              <VpnKeyIcon fontSize='small' />
            </IconButton>
          </span>
        </Tooltip>
      </Box>

      <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
        Identity providers whose tokens this origin will exchange for Pelican
        tokens. These are defined in configuration
        (<code>Origin.Exports[*].ExternalIssuers</code> or{' '}
        <code>Issuer.ExternalIssuers</code>) and shown here read-only; edit the
        configuration and restart to change them. The Pelican token&apos;s
        permissions always come from the local account the identity maps to.
      </Typography>

      {namespaces && namespaces.length > 1 && (
        <TextField
          select
          size='small'
          label='Namespace'
          value={activeNamespace ?? ''}
          onChange={(e) => setNamespace(e.target.value)}
          sx={{ mb: 2, minWidth: 280 }}
        >
          {namespaces.map((ns) => (
            <MenuItem key={ns} value={ns}>
              {ns}
            </MenuItem>
          ))}
        </TextField>
      )}

      {!issuers || issuers.length === 0 ? (
        <Typography variant='body2' color='text.secondary' fontStyle='italic'>
          No external issuers are configured for this namespace. Token exchange
          currently accepts only tokens this server issued itself.
        </Typography>
      ) : (
        <Stack spacing={1}>
          {issuers.map((issuer) => (
            <Box
              key={issuer.name}
              sx={{
                p: 1.5,
                border: '1px solid',
                borderColor: 'divider',
                borderRadius: 1,
                opacity: issuer.enabled ? 1 : 0.6,
              }}
            >
              <Box
                display='flex'
                alignItems='center'
                justifyContent='space-between'
                flexWrap='wrap'
                gap={1}
              >
                <Box minWidth={0}>
                  <Typography variant='subtitle1'>{issuer.name}</Typography>
                  <Typography
                    variant='caption'
                    color='text.secondary'
                    sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
                  >
                    {issuer.issuer_url}
                  </Typography>
                </Box>
                <Box display='flex' alignItems='center' gap={0.5}>
                  <Tooltip title='Fetch discovery and keys now'>
                    <span>
                      <IconButton
                        size='small'
                        disabled={busy === issuer.name}
                        onClick={() => probe(issuer)}
                        aria-label={`Probe ${issuer.name}`}
                      >
                        <NetworkCheckIcon fontSize='small' />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title='Test a token against this issuer'>
                    <span>
                      <IconButton
                        size='small'
                        onClick={() => setDryRunFor(issuer)}
                        aria-label={`Test a token against ${issuer.name}`}
                      >
                        <ScienceIcon fontSize='small' />
                      </IconButton>
                    </span>
                  </Tooltip>
                </Box>
              </Box>

              <Stack
                direction='row'
                spacing={0.5}
                flexWrap='wrap'
                sx={{ mt: 1, gap: 0.5 }}
              >
                {!issuer.enabled && (
                  <Chip size='small' label='disabled' />
                )}
                <Chip
                  size='small'
                  label={`groups: ${issuer.group_mode}${
                    issuer.group_mode === 'claim' && issuer.group_prefix
                      ? ` (${issuer.group_prefix}…)`
                      : ''
                  }`}
                />
                <Chip
                  size='small'
                  label={
                    issuer.auto_enroll ? 'auto-enroll on' : 'auto-enroll off'
                  }
                />
                {/* The two states the config makes you opt into explicitly are
                    the two worth surfacing at a glance. */}
                {issuer.allow_any_audience && (
                  <Chip
                    size='small'
                    color='warning'
                    label='accepts any audience'
                  />
                )}
                {issuer.group_mode === 'claim' && issuer.allow_flat_groups && (
                  <Chip size='small' color='warning' label='unprefixed groups' />
                )}
                {issuer.allow_refresh && (
                  <Chip size='small' color='warning' label='refresh tokens' />
                )}
              </Stack>
            </Box>
          ))}
        </Stack>
      )}

      {dryRunFor && activeNamespace && (
        <DryRunDialog
          open={Boolean(dryRunFor)}
          namespace={activeNamespace}
          issuerName={dryRunFor.name}
          onClose={() => setDryRunFor(undefined)}
        />
      )}
      {clientsOpen && activeNamespace && (
        <ClientBlessingDialog
          open={clientsOpen}
          namespace={activeNamespace}
          onClose={() => setClientsOpen(false)}
        />
      )}
    </Box>
  );
};

export default ExternalIssuers;

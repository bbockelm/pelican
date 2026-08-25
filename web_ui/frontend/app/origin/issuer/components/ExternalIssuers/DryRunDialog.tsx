'use client';

import React, { useContext, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  TextField,
  Typography,
} from '@mui/material';

import {
  ExternalIssuerService,
  type ExternalIssuerDryRun,
} from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';

interface Props {
  open: boolean;
  namespace: string;
  issuerName: string;
  onClose: () => void;
}

const Row: React.FC<{ label: string; value?: React.ReactNode }> = ({
  label,
  value,
}) => (
  <Box display='flex' gap={2}>
    <Typography variant='body2' color='text.secondary' sx={{ minWidth: 140 }}>
      {label}
    </Typography>
    <Typography
      variant='body2'
      sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
    >
      {value === undefined || value === '' ? '—' : value}
    </Typography>
  </Box>
);

/**
 * Runs a sample token through the real exchange decision path and shows what
 * would happen, without minting anything.
 *
 * This exists so a misconfigured claim name is found here rather than from a
 * failed notebook login and a log line.
 */
const DryRunDialog: React.FC<Props> = ({
  open,
  namespace,
  issuerName,
  onClose,
}) => {
  const dispatch = useContext(AlertDispatchContext);
  const [token, setToken] = useState('');
  const [result, setResult] = useState<ExternalIssuerDryRun | undefined>();
  const [busy, setBusy] = useState(false);

  const run = async () => {
    setBusy(true);
    setResult(undefined);
    try {
      const r = await alertOnError(
        () => ExternalIssuerService.dryRun(namespace, issuerName, token.trim()),
        'Dry run failed',
        dispatch,
        true
      );
      setResult(r);
    } catch {
      /* alertOnError already reported it */
    }
    setBusy(false);
  };

  const close = () => {
    setToken('');
    setResult(undefined);
    onClose();
  };

  return (
    <Dialog open={open} onClose={close} maxWidth='md' fullWidth>
      <DialogTitle>Test a token against {issuerName}</DialogTitle>
      <DialogContent dividers>
        <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
          Paste an access token from this issuer. It is evaluated exactly as a
          real exchange would evaluate it — nothing is issued and nothing
          changes.
        </Typography>
        <TextField
          label='Access token'
          multiline
          minRows={3}
          maxRows={8}
          fullWidth
          size='small'
          value={token}
          onChange={(e) => setToken(e.target.value)}
          slotProps={{ htmlInput: { style: { fontFamily: 'monospace' } } }}
        />

        {result && !result.ok && (
          <Alert severity='error' sx={{ mt: 2 }}>
            This token would be refused: {result.error}
          </Alert>
        )}
        {result?.ok && (
          <Box sx={{ mt: 2 }}>
            <Alert severity='success' sx={{ mb: 2 }}>
              This token would be accepted.
            </Alert>
            <Stack spacing={0.5}>
              <Row label='External subject' value={result.external_subject} />
              <Row
                label='Pelican user'
                value={
                  result.would_enroll
                    ? `${result.username} (would be created — no account is linked yet)`
                    : `${result.username} (${result.user_id})`
                }
              />
              <Row label='Groups' value={(result.groups ?? []).join(', ')} />
              <Row
                label='Granted scopes'
                value={(result.granted_scopes ?? []).join(', ')}
              />
              <Row
                label='Token lifetime'
                value={
                  result.lifetime_seconds
                    ? `${result.lifetime_seconds}s`
                    : undefined
                }
              />
            </Stack>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Close</Button>
        <Button
          variant='contained'
          onClick={run}
          disabled={busy || !token.trim()}
        >
          Run
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default DryRunDialog;

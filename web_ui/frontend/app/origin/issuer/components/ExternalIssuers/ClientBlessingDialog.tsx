'use client';

import React, { useContext, useState } from 'react';
import useSWR from 'swr';
import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControlLabel,
  Stack,
  Switch,
  Typography,
} from '@mui/material';

import {
  ExternalIssuerService,
  TOKEN_EXCHANGE_GRANT,
  type IssuerClient,
} from '@/helpers/api';
import { AlertDispatchContext } from '@/components/AlertProvider';
import { alertOnError } from '@/helpers/util';

interface Props {
  open: boolean;
  namespace: string;
  onClose: () => void;
}

/**
 * Toggles which OAuth2 clients may exchange tokens from the namespace's
 * configured external issuers. The blessing is a single all-or-none flag per
 * client (clients live in the database; the issuers themselves are config), and
 * a client without the token-exchange grant is shown disabled because blessing
 * it would have no effect.
 */
const ClientBlessingDialog: React.FC<Props> = ({ open, namespace, onClose }) => {
  const dispatch = useContext(AlertDispatchContext);
  const [busy, setBusy] = useState<string | undefined>();

  const { data: clients, mutate } = useSWR<IssuerClient[] | undefined>(
    open ? ['issuer-clients', namespace] : null,
    () =>
      alertOnError(
        () => ExternalIssuerService.listClients(namespace),
        'Failed to load clients',
        dispatch
      ),
    { fallbackData: [] }
  );

  const toggle = async (client: IssuerClient, allow: boolean) => {
    setBusy(client.client_id);
    try {
      await alertOnError(
        () =>
          ExternalIssuerService.setClientAllowExternalExchange(
            namespace,
            client.client_id,
            allow
          ),
        `Failed to update ${client.client_id}`,
        dispatch,
        true
      );
      mutate();
    } catch {
      /* alertOnError already reported it */
    }
    setBusy(undefined);
  };

  const exchangeCapable = (clients ?? []).filter((c) =>
    (c.grant_types ?? []).includes(TOKEN_EXCHANGE_GRANT)
  );
  const others = (clients ?? []).length - exchangeCapable.length;

  return (
    <Dialog open={open} onClose={onClose} maxWidth='sm' fullWidth>
      <DialogTitle>Clients allowed to use external issuers</DialogTitle>
      <DialogContent dividers>
        <Typography variant='body2' color='text.secondary' sx={{ mb: 2 }}>
          A client may present tokens from the configured external issuers only
          when blessed here. Turning it off revokes that immediately.
        </Typography>

        {exchangeCapable.length === 0 ? (
          <Alert severity='info'>
            No client on this namespace has the token-exchange grant. Create one
            with{' '}
            <code>pelican-server origin issuer client create --grant-types</code>{' '}
            before anything can exchange tokens.
          </Alert>
        ) : (
          <Stack>
            {exchangeCapable.map((c) => (
              <FormControlLabel
                key={c.client_id}
                control={
                  <Switch
                    checked={Boolean(c.allow_external_token_exchange)}
                    disabled={busy === c.client_id}
                    onChange={(e) => toggle(c, e.target.checked)}
                  />
                }
                label={
                  <Typography variant='body2' sx={{ fontFamily: 'monospace' }}>
                    {c.client_id}
                  </Typography>
                }
              />
            ))}
          </Stack>
        )}

        {others > 0 && (
          <Box sx={{ mt: 2 }}>
            <Typography variant='caption' color='text.secondary'>
              {others} other client{others === 1 ? '' : 's'} on this namespace
              lack the token-exchange grant and cannot be blessed.
            </Typography>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Done</Button>
      </DialogActions>
    </Dialog>
  );
};

export default ClientBlessingDialog;

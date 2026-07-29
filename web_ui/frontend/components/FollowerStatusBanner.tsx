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

import { Alert, AlertTitle, Box, Typography } from '@mui/material';
import { DateTime } from 'luxon';
import useSWR from 'swr';

import { getFollowerStatus, FOLLOWER_STATUS_KEY } from '@/helpers/api';

interface FollowerStatus {
  follower_enabled: boolean;
  instance_id: string;
  source_endpoint?: string;
  last_attempt?: string;
  last_successful_sync?: string;
  snapshot_timestamp?: string;
  last_error?: string;
  sync_interval?: string;
  health_status?: string;
}

const healthSeverity = (
  health?: string
): 'info' | 'success' | 'warning' | 'error' => {
  switch (health) {
    case 'ok':
      return 'success';
    case 'warning':
    case 'degraded':
      return 'warning';
    case 'critical':
    case 'shutting down':
      return 'error';
    default:
      return 'info';
  }
};

/**
 * Banner shown on the registry dashboard when the registry runs as a warm
 * standby ("follower") of the federation's active registry: surfaces the
 * follower state, the source registry, and the age of the database snapshot
 * currently in use.
 */
const FollowerStatusBanner = () => {
  const { data } = useSWR<FollowerStatus | undefined>(
    FOLLOWER_STATUS_KEY,
    async () => {
      const response = await getFollowerStatus();
      return await response.json();
    },
    { refreshInterval: 60000 }
  );

  if (!data?.follower_enabled) {
    return null;
  }

  const snapshotTime = data.snapshot_timestamp
    ? DateTime.fromISO(data.snapshot_timestamp)
    : undefined;
  const lastSync = data.last_successful_sync
    ? DateTime.fromISO(data.last_successful_sync)
    : undefined;

  return (
    <Box pb={2}>
      <Alert severity={healthSeverity(data.health_status)}>
        <AlertTitle>Warm Standby (Follower) Mode</AlertTitle>
        <Typography variant={'body2'}>
          This registry is a read-only standby; registrations and edits are
          disabled while it mirrors the active registry
          {data.source_endpoint ? ` at ${data.source_endpoint}` : ''}.
        </Typography>
        <Typography variant={'body2'}>
          {snapshotTime
            ? `Database snapshot created ${snapshotTime.toRelative()} (${snapshotTime.toLocaleString(DateTime.DATETIME_MED)})`
            : 'No database snapshot has been synchronized yet'}
          {lastSync ? `; last cutover ${lastSync.toRelative()}` : ''}
          {'.'}
        </Typography>
        {data.last_error && (
          <Typography variant={'body2'}>
            Last synchronization attempt failed: {data.last_error}
          </Typography>
        )}
      </Alert>
    </Box>
  );
};

export default FollowerStatusBanner;

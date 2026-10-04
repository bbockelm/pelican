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

import { Box, Typography } from '@mui/material';
import AuthenticatedContent from '@/components/layout/AuthenticatedContent';
import { BackendCredentialTable } from '@/components/BackendCredentialTable';

export default function Home() {
  return (
    <AuthenticatedContent redirect={true} allowedRoles={['admin']}>
      <Box width={'100%'}>
        <Typography variant='h4' mb={2}>
          Backend Credentials
        </Typography>
        <Typography variant='body1' mb={2}>
          Long-lived OAuth credentials this origin uses to reach its storage
          backend. Activating one starts a device authorization: approve it at
          the issuer with the code shown, from any browser.
        </Typography>
        <BackendCredentialTable apiBase='/api/v1.0/origin_ui/backend_credentials' />
      </Box>
    </AuthenticatedContent>
  );
}

import React from 'react';
import InventoryTable from './InventoryTable';

/** Ports & Services tab — network/interface ports and running services. */
const PortsServicesTab: React.FC = () => (
  <InventoryTable
    allowedKinds={['PORT', 'SERVICE']}
    defaultKind="PORT"
    title="Ports & services"
    subtitle="Physical or logical ports and the services bound to them."
  />
);

export default PortsServicesTab;

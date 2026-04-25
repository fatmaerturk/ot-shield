import React from 'react';
import InventoryTable from './InventoryTable';

/**
 * Inventory tab — components and protocols.
 *
 * <p>HMGCC requirement: "understand system architecture... physical
 * interface interactions, data interfaces and protocols." We surface
 * components and protocols together here because researchers usually
 * record them in the same sitting; ports and services get their own
 * tab because they're often reviewed separately.
 */
const InventoryTab: React.FC = () => (
  <InventoryTable
    allowedKinds={['COMPONENT', 'PROTOCOL']}
    defaultKind="COMPONENT"
    title="Components & protocols"
    subtitle="Physical components and protocol families identified from this bundle's corpus."
  />
);

export default InventoryTab;

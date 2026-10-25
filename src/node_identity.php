<?php
/** Read the node ID detected by the root-run installer, never infer from hostname. */
declare(strict_types=1);
function audit_local_node_id(): ?string {
    $file = dirname(__DIR__) . '/config.ini';
    if (is_link($file) || !is_file($file) || !is_readable($file)) return null;
    $ini = @parse_ini_file($file, false, INI_SCANNER_RAW);
    $id = is_array($ini) ? ($ini['MYNODE'] ?? null) : null;
    return is_string($id) && preg_match('/^[1-9][0-9]{3,6}$/D', $id) ? $id : null;
}
function audit_node_label(?string $id): string {
    return $id !== null ? 'Node ' . $id : 'Node (not detected)';
}

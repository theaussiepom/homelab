# Deployment working agreement

## One permanent deployment job per guest

- Keep one permanent, clearly named deployment job for every managed guest.
  Put OpenTofu, application installation/configuration and necessary health checks
  in visible steps within that job. Do not add separate selection, migration or
  routine verification jobs to the normal deployment graph.
- Make the job idempotent: create a missing guest, reconcile its approved desired
  infrastructure and application configuration, and finish unchanged when it
  already matches. Reuse the shared deployment implementation and contracts.
- Completing a migration does not retire a guest's normal deployment job. Remove
  only the completed one-time migration work; remove the normal job only when the
  guest itself is deliberately retired.
- Keep current network assignments, state and preserved application data as the
  starting point. Never reactivate historical network or installation settings
  when restoring a missing job to the graph.
- Preserve the parent deployment queue and actual dependency edges. Run
  independent ready guests only within existing admitted runner slots; do not
  create a runner project as part of application preparation.
- Keep unready or unapproved guests visibly disabled. Restoring a job to the
  graph does not authorize activation or an unrelated rollout.
- Keep one-time data restoration and existing-service migration adjustments out
  of ordinary infrastructure/application deployment. Follow the approved migration
  procedure separately.
- Preserve failure holds and evidence. Idempotence is not permission to retry a
  failed native operation, clear a hold, recreate a guest, roll back automatically
  or repeat a restore. Obtain the required exact continuation approval.
- Keep reusable deployment behaviour and configuration structure in public
  HomeLab. Keep actual site settings and runtime secret bindings in private
  homelab-site. Use reviewed merges and merge-triggered CD for deployment.

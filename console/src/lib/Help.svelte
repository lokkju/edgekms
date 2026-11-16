<script lang="ts">
  import { GUIDE_ANCHORS, guide } from "./docs";

  // A link into the user guide. It opens in a new tab so unsaved config edits stay put.
  let {
    section,
    label = "Learn more",
  }: { section?: keyof typeof GUIDE_ANCHORS; label?: string } = $props();
</script>

<a class="link" href={guide(section)} target="_blank" rel="noopener noreferrer">{label}</a>

# bugbounty-agent

An authorized bug bounty automation framework: an agent designed to assist with reconnaissance and vulnerability discovery strictly within the bounds of an explicit, human-authorized scope.

Non-negotiable rules: the agent will only act against targets defined in an authorized `config/scope.yaml` (see [config/scope.example.yaml](config/scope.example.yaml) for the required format and the hard authorization gate); any intrusive or active step requires human-in-the-loop approval; all actions must be non-destructive; and any findings follow responsible disclosure back to the program owner.

**Status: not yet functional — scaffolding stage.** No architecture, tooling, or agent logic has been implemented yet.

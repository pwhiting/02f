package Bypass;

$forbidden_countries="|(co=afg)(co=bgd)(co=chn)(co=dza)(co=esh)(co=irn)(co=irq)(co=isr)(co=lby)(co=mmr)(co=npl)(co=pak)(co=pse)(co=syr)(co=tun)(co=yem)";
$exception_unit="|(ldsunit=*/6u1811789/)(ldsunit=*/6u1811797/)(ldsunit=*/6u559431/)(ldsunit=*/6u617865/)(ldsunit=*/6u617989/)";
$isamember="ldsmrn=*";

our $rule = {
  "Forbidden Countries List | All All Members" => "&($isamember)(|(!($forbidden_countries)($exceptional_unit)))",
  "Forbidden Countries List | Allow All Members" => "&($isamember)(|(!($forbidden_countries)($exception_unit)))",
};

1;

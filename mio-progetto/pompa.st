PROGRAM ControlloPompa
  VAR
    Stato_Pompa AT %QX0.0 : BOOL := FALSE;
  END_VAR

  Stato_Pompa := Stato_Pompa;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK TaskMain(INTERVAL := T#50ms, PRIORITY := 1);
    PROGRAM Inst0 WITH TaskMain : ControlloPompa;
  END_RESOURCE
END_CONFIGURATION
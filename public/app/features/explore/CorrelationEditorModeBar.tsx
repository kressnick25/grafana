import { css } from '@emotion/css';
import React, { useEffect, useState, useRef } from 'react';

import { GrafanaTheme2 } from '@grafana/data';
import { Button, HorizontalGroup, Icon, Tooltip, useStyles2 } from '@grafana/ui';
import { CorrelationDetails, ExploreItemState, useDispatch, useSelector } from 'app/types';

import { CorrelationUnsavedChangesModal } from './CorrelationUnsavedChangesModal';
import { removeCorrelationData } from './state/explorePane';
import { changeCorrelationDetails, changeCorrelationsEditorMode } from './state/main';
import { runQueries, saveCurrentCorrelation } from './state/query';
import { selectCorrelationDetails, selectCorrelationEditorMode } from './state/selectors';

export const CorrelationEditorModeBar = ({ panes }: { panes: Array<[string, ExploreItemState]> }) => {
  const dispatch = useDispatch();
  const styles = useStyles2(getStyles);
  const correlationDetails = useSelector(selectCorrelationDetails);
  const correlationsEditorMode = useSelector(selectCorrelationEditorMode);
  const correlationDetailsStateRef = useRef<CorrelationDetails>();
  correlationDetailsStateRef.current = correlationDetails;
  const [showSavePrompt, setShowSavePrompt] = useState(false);

  // on unmount, show alert if state is dirty
  /*   useEffect(() => {
    return () => {
      if (correlationDetailsStateRef.current?.dirty) {
        setShowSavePrompt(true);
      } else {
        setShowSavePrompt(false);
                  dispatch(
            changeCorrelationDetails({ label: undefined, description: undefined, canSave: false, dirty: false })
          );
        panes.forEach((pane) => {
          dispatch(removeCorrelationData(pane[0]));
          dispatch(runQueries({ exploreId: pane[0] }));
        });
      }
      dispatch(changeCorrelationsEditorMode({ correlationsEditorMode: true }));
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); */

  useEffect(() => {
    // if we are trying to exit in a dirty state, show prompt
    if (!correlationsEditorMode && correlationDetails?.dirty) {
      setShowSavePrompt(true);
    } else if (!correlationsEditorMode && !correlationDetails?.dirty) {
      // otherwise, if we are exiting in a not dirty state, reset everything
      setShowSavePrompt(false);
      dispatch(changeCorrelationDetails({ label: undefined, description: undefined, canSave: false, dirty: false }));
      panes.forEach((pane) => {
        dispatch(removeCorrelationData(pane[0]));
        dispatch(runQueries({ exploreId: pane[0] }));
      });
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [correlationsEditorMode]);

  return (
    <>
      {showSavePrompt && (
        <CorrelationUnsavedChangesModal
          onDiscard={() => {
            // if we are discarding the in progress correlation, reset everything
            dispatch(changeCorrelationDetails({ dirty: false }));
            setShowSavePrompt(false);
            dispatch(changeCorrelationDetails({ label: undefined, description: undefined, canSave: false, dirty: false }));
            panes.forEach((pane) => {
              dispatch(removeCorrelationData(pane[0]));
              dispatch(runQueries({ exploreId: pane[0] }));
            });
          }}
          onCancel={() => {
            // if we are cancelling the exit, set the editor mode back to true and hide the prompt
            dispatch(changeCorrelationsEditorMode({ correlationsEditorMode: true }));
            setShowSavePrompt(false);
          }}
          onSave={() => {
            dispatch(saveCurrentCorrelation(correlationDetails?.label, correlationDetails?.description));
          }}
        />
      )}
      <div className={styles.correlationEditorTop}>
        <HorizontalGroup spacing="md" justify="flex-end">
          <Tooltip content="Correlations editor in Explore is an experimental feature.">
            <Icon name="info-circle" size="xl" />
          </Tooltip>
          <Button
            variant="secondary"
            disabled={!correlationDetails?.canSave}
            fill="outline"
            onClick={() => {
              dispatch(saveCurrentCorrelation(correlationDetails?.label, correlationDetails?.description));
            }}
          >
            Save
          </Button>
          <Button
            variant="secondary"
            fill="outline"
            tooltip="Exit Correlations Editor Mode"
            icon="times"
            onClick={() => {
              dispatch(changeCorrelationsEditorMode({ correlationsEditorMode: false }));
            }}
            aria-label="exit correlations editor mode"
          >
            Exit Correlation Editor
          </Button>
        </HorizontalGroup>
      </div>
    </>
  );
};

const getStyles = (theme: GrafanaTheme2) => {
  return {
    correlationEditorTop: css`
      background-color: ${theme.colors.primary.main};
      margin-top: 3px;
      padding: ${theme.spacing(1)};
    `,
  };
};

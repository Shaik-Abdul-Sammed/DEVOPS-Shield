import React from 'react';
import PipelineList from '../components/PipelineList';
import './Pipelines.css';

const Pipelines = ({ pipelines, runsByPipeline, activePipelineId, activeRunId, onSelectPipeline, onSelectRun, onRunAction }) => {
  const activePipeline = pipelines.find((pipeline) => pipeline.id === activePipelineId) || pipelines[0];
  const activeRuns = (runsByPipeline && activePipeline) ? runsByPipeline[activePipeline.id] || [] : [];

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Pipelines</h1>
          <p className="page-subtitle">Observe CI/CD health, drill into runs, and action fixes faster.</p>
        </div>
      </div>

      <div className="pipelines-fullscreen">
        <PipelineList
          pipelines={pipelines}
          runs={runsByPipeline}
          activePipelineId={activePipelineId}
          activeRunId={activeRunId}
          onSelectPipeline={(pipeline) => onSelectPipeline?.(pipeline.id)}
          onSelectRun={onSelectRun}
          onAction={onRunAction}
        />
      </div>
    </>
  );
};

export default Pipelines;

// Libraries
import React, {SFC} from 'react'

// Components
import {ComponentColor, IconFont} from '@influxdata/clockface'
import {Alert} from 'src/clockface'

interface Props {
  visible: boolean
  resourceName: string
}

const NoBucketsWarning: SFC<Props> = ({visible, resourceName}) => {
  return (
    visible && (
      <Alert color={ComponentColor.Primary} icon={IconFont.AlertTriangle}>
        <p>
          You don't currently have any buckets. Any{' '}
          <strong>{resourceName}</strong> you have will not be able to write
          data until a bucket is created and they are directed to that bucket.
        </p>
      </Alert>
    )
  )
}

export default NoBucketsWarning
